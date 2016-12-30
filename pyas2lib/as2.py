from __future__ import absolute_import
from __future__ import unicode_literals
from .compat import str_cls, byte_cls, parse_mime
from .cms import compress_message, decompress_message, decrypt_message, \
    encrypt_message, verify_message, sign_message
from .utils import canonicalize, mime_to_string, mime_to_bytes
from email import utils as email_utils
from email import message as email_message
from email import encoders
from email.mime.multipart import MIMEMultipart
from oscrypto import asymmetric
from uuid import uuid1
from .exceptions import *
import logging
import hashlib

logger = logging.getLogger('pyas2lib')


class Organization(object):

    def __init__(self, as2_id, sign_key=None, sign_key_pass=None,
                 decrypt_key=None, decrypt_key_pass=None):
        self.as2_id = as2_id

        # TODO: Need to give option to include CA certificates

        if sign_key:
            self.sign_key = asymmetric.load_pkcs12(
                sign_key, byte_cls(sign_key_pass))
        else:
            self.sign_key = None
        self.decrypt_key = asymmetric.load_pkcs12(
            decrypt_key, byte_cls(decrypt_key_pass)) if decrypt_key else None

        # TODO: Need to verify the certificate here.


class Partner(object):

    def __init__(self, as2_id, verify_cert=None, encrypt_cert=None,
                 indefinite_length=False):
        self.as2_id = as2_id

        # TODO: Need to give option to include CA certificates

        self.verify_cert = asymmetric.load_certificate(
            verify_cert) if verify_cert else None
        self.encrypt_cert = asymmetric.load_certificate(
            encrypt_cert) if encrypt_cert else None
        self.indefinite_length = indefinite_length

        # TODO: Need to verify the certificate here.


class Message(object):
    """Class for handling AS2 messages. Includes functions for both
    parsing and building messages.

    """

    AS2_VERSION = '1.2'
    MIME_VERSION = '1.0'
    EDIINT_FEATURES = 'CMS'
    DIGEST_ALGORITHMS = (
        'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'
    )
    ENCRYPTION_ALGORITHMS = (
        'tripledes_192_cbc',
        'rc2_128_cbc',
        'rc4_128_cbc',
    )

    MDN_MODES = (
        'SYNC', 'ASYNC'
    )

    def __init__(self, compress=False, sign=False, digest_alg='sha256',
                 encrypt=False, enc_alg='tripledes_192_cbc', mdn_mode=None,
                 mdn_digest_alg=None, mdn_url=None):
        """
        :param compress: Set this flag to True to compress outgoing
            messages. (default `False`)

        :param sign: Set this flag to True to sign outgoing
            messages. (default `False`)

        :param digest_alg: The digest algorithm to be used for generating the
            signature. (default "sha256")

        :param encrypt: Set this flag to True to encrypt outgoing
            messages. (default `False`)

        :param enc_alg:
            The encryption algorithm to be used. (default `"tripledes_192_cbc"`)

        :param mdn_mode: The mode to be used for receiving the MDN.
            Set to `None` for no MDN, `'SYNC'` for synchronous and `'ASYNC'`
            for asynchronous. (default `None`)

        :param mdn_digest_alg: The digest algorithm to be used by the receiver
            for signing the MDN. Use `None` for unsigned MDN. (default `None`)

        :param mdn_url: The URL where the receiver is expected to post
            asynchronous MDNs.
        """

        # Validations
        if digest_alg not in Message.DIGEST_ALGORITHMS:
            raise ImproperlyConfigured(
                'Unsupported Digest Algorithm {}, must be '
                'one of {}'.format(digest_alg, Message.DIGEST_ALGORITHMS))

        if enc_alg not in Message.ENCRYPTION_ALGORITHMS:
            raise ImproperlyConfigured(
                'Unsupported Encryption Algorithm {}, must be '
                'one of {}'.format(enc_alg, Message.ENCRYPTION_ALGORITHMS))

        if mdn_mode and mdn_mode not in Message.MDN_MODES:
            raise ImproperlyConfigured(
                'Unsupported MDN Mode {}, must be '
                'one of {}'.format(digest_alg, Message.MDN_MODES))

        if mdn_mode == 'ASYNC' and not mdn_url:
            raise ImproperlyConfigured(
                'mdn_url is mandatory when mdn_mode is set to ASYNC ')

        if mdn_digest_alg and mdn_digest_alg not in Message.DIGEST_ALGORITHMS:
            raise ImproperlyConfigured(
                'Unsupported MDN Digest Algorithm {}, must be '
                'one of {}'.format(mdn_digest_alg, Message.DIGEST_ALGORITHMS))

        # Assignments
        self.compress = compress
        self.sign = sign
        self.digest_alg = digest_alg
        self.encrypt = encrypt
        self.enc_alg = enc_alg
        self.mdn_mode = mdn_mode
        self.mdn_digest_alg = mdn_digest_alg
        self.mdn_url = mdn_url
        self.message_id = None
        self.headers = {}
        self.payload = None

    def __str__(self):
        if self.payload and self.headers:
            for k, v in self.headers.items():
                self.payload[k] = v
            return mime_to_string(self.payload, 78)
        else:
            return ''

    def __bytes__(self):
        if self.payload and self.headers:
            for k, v in self.headers.items():
                self.payload[k] = v
            return mime_to_bytes(self.payload, 78)
        else:
            return ''

    def build(self, sender, receiver, data, filename=None,
              subject='AS2 Message', content_type='application/edi-consent',
              additional_headers=None):

        """Function builds the AS2 message. Compresses, signs and encrypts
        the payload if applicable.

        :param sender:
            An object of type <pyas2lib.as2.Organization>, representing the
            sender of the message.

        :param receiver:
            An object of type <pyas2lib.as2.Partner>, representing the
            receiver of the message .

        :param data: A byte string of the data to be transmitted.

        :param filename:
            Optional filename to be included in the Content-disposition header.

        :param subject:
            The subject for the AS2 message, used by some AS2 servers for
            additional routing of messages. (default "AS2 Message")

        :param content_type:
            The content type for the AS2 message, to be used in the MIME
            header. (default "application/edi-consent")

        :param additional_headers:
            Any additional headers to be included as part of the AS2 message.

        :return:
            The MIC Hash of the sent message to be used while verifying
            the MDN.
        """

        # Validations
        assert isinstance(sender, Organization), \
            'Parameter sender must be of type {}'.format(Organization)
        assert isinstance(receiver, Partner), \
            'Parameter receiver must be of type {}'.format(Partner)
        assert type(data) is byte_cls, \
            'Parameter data must be of type {}'.format(byte_cls)
        additional_headers = additional_headers if additional_headers else {}
        assert type(additional_headers) is dict

        if self.sign and not sender.sign_key:
            raise ImproperlyConfigured(
                'Signing of messages is enabled but sign key is not set '
                'for the sender.')

        if self.encrypt and not receiver.encrypt_cert:
            raise ImproperlyConfigured(
                'Encryption of messages is enabled but encrypt key is not set '
                'for the receiver.')

        # Generate message id using UUID 1 as it uses both hostname and time
        self.message_id = str(uuid1())

        # Set up the message headers
        self.headers = {
            'AS2-Version': Message.AS2_VERSION,
            'ediint-features': Message.EDIINT_FEATURES,
            'MIME-Version': Message.MIME_VERSION,
            'Message-ID': '<{}>'.format(self.message_id),
            'AS2-From': sender.as2_id,
            'AS2-To': receiver.as2_id,
            'Subject': subject,
            'Date': email_utils.formatdate(localtime=True),
            # 'recipient-address': message.partner.target_url,
        }
        self.headers.update(additional_headers)

        # Read the input and convert to bytes if value is unicode/str
        # using utf-8 encoding and finally Canonicalize the payload
        mic = None
        self.payload = email_message.Message()
        self.payload.set_payload(data)
        self.payload.set_type(content_type)
        encoders.encode_7or8bit(self.payload)

        if filename:
            self.payload.add_header(
                'Content-Disposition', 'attachment', filename=filename)
        del self.payload['MIME-Version']

        if self.compress:
            compressed_message = email_message.Message()
            compressed_message.set_type('application/pkcs7-mime')
            compressed_message.set_param('name', 'smime.p7z')
            compressed_message.set_param('smime-type', 'compressed-data')
            compressed_message.add_header(
                'Content-Disposition', 'attachment', filename='smime.p7z')
            compressed_message.set_payload(
                compress_message(canonicalize(self.payload)))
            encoders.encode_base64(compressed_message)
            self.payload = compressed_message

        if self.sign:
            signed_message = MIMEMultipart(
                'signed', protocol="application/pkcs7-signature")
            del signed_message['MIME-Version']
            signed_message.attach(self.payload)

            # Calculate the MIC Hash of the message to be verified
            mic_content = canonicalize(self.payload)
            digest_func = hashlib.new(self.digest_alg)
            digest_func.update(mic_content)
            mic = digest_func.hexdigest()

            # Create the signature mime message
            signature = email_message.Message()
            signature.set_type('application/pkcs7-signature')
            signature.set_param('name', 'smime.p7s')
            signature.set_param('smime-type', 'signed-data')
            signature.add_header(
                'Content-Disposition', 'attachment', filename='smime.p7z')
            del signature['MIME-Version']
            signature.set_payload(sign_message(
                mic_content, self.digest_alg, sender.sign_key))
            encoders.encode_base64(signature)
            signed_message.set_param('micalg', self.digest_alg)
            signed_message.attach(signature)
            self.payload = signed_message

        if self.encrypt:
            encrypted_message = email_message.Message()
            encrypted_message.set_type('application/pkcs7-mime')
            encrypted_message.set_param('name', 'smime.p7m')
            encrypted_message.set_param('smime-type', 'enveloped-data')
            encrypted_message.add_header(
                'Content-Disposition', 'attachment', filename='smime.p7m')
            encrypted_message.set_payload(encrypt_message(
                # mime_to_bytes(self.payload, 0),
                canonicalize(self.payload),
                self.enc_alg,
                receiver.encrypt_cert
            ))
            encoders.encode_base64(encrypted_message)
            self.payload = encrypted_message

        if self.mdn_mode:
            self.headers['disposition-notification-to'] = 'no-reply@pyas2.com'
            if self.mdn_digest_alg:
                self.headers['disposition-notification-options'] = \
                    'signed-receipt-protocol=required, pkcs7-signature; ' \
                    'signed-receipt-micalg=optional, %s' % self.mdn_digest_alg
            if self.mdn_mode.mdn_mode == 'ASYNC':
                self.headers['receipt-delivery-option'] = self.mdn_url

        return mic

    def parse(self, raw_content, find_org_cb, find_partner_cb):
        """Function parses the RAW AS2 message; decrypts, verifies and
        decompresses it and extracts the payload.

        :param raw_content:
            A byte string of the received HTTP headers followed by the body.

        :param find_org_cb:
            A callback the returns an Organization object if exists. The
            as2-to header value is passed as an argument to it.

        :param find_partner_cb:
            A callback the returns an Partner object if exists. The
            as2-from header value is passed as an argument to it.

        :return:
            The MIC Hash of the received message to be used while building
            the MDN.
        """

        # Parse the raw MIME message and extract its content and headers
        self.payload = parse_mime(raw_content)
        mic = None
        for k, v in self.payload.items():
            if k.lower() == 'message-id':
                self.message_id = v.lstrip('<').rstrip('>')
            self.headers[k] = v

        # Get the organization and partner for this transmission
        organization = find_org_cb(self.headers)
        partner = find_partner_cb(self.headers)

        if self.encrypt and \
                self.payload.get_content_type() != 'application/pkcs7-mime':
            pass

        if self.payload.get_content_type() == 'application/pkcs7-mime' \
                and self.payload.get_param('smime-type') == 'enveloped-data':
            self.encrypt = True
            self.enc_alg, decrypted_content = decrypt_message(
                self.payload.get_payload(decode=True),
                organization.decrypt_key,
                partner.indefinite_length
            )
            self.payload = parse_mime(decrypted_content)

            if self.payload.get_content_type() == 'text/plain':
                self.payload = email_message.Message()
                self.payload.set_payload(decrypted_content)
                self.payload.set_type('application/edi-consent')

        if self.sign and \
                self.payload.get_content_type() != 'multipart/signed':
            pass

        if self.payload.get_content_type() == 'multipart/signed':
            self.sign = True
            signature = None
            for part in self.payload.walk():
                if part.get_content_type() == "application/pkcs7-signature":
                    signature = part.get_payload(decode=True)
                else:
                    self.payload = part

            # Verify the message
            mic_content = canonicalize(self.payload)
            self.digest_alg = verify_message(
                mic_content,
                signature,
                partner.verify_cert
            )

            # Calculate the MIC Hash of the message to be verified
            digest_func = hashlib.new(self.digest_alg)
            digest_func.update(mic_content)
            mic = digest_func.hexdigest()

        if self.payload.get_content_type() == 'application/pkcs7-mime' \
                and self.payload.get_param('smime-type') == 'compressed-data':
            self.compress = True
            decompressed_data = decompress_message(
                self.payload.get_payload(decode=True),
                partner.indefinite_length
            )
            self.payload = parse_mime(decompressed_data)

        return mic
