from __future__ import absolute_import, unicode_literals
from .compat import str_cls, byte_cls, parse_mime
from .cms import compress_message, decompress_message, decrypt_message, \
    encrypt_message, verify_message, sign_message
from .cms import DIGEST_ALGORITHMS, ENCRYPTION_ALGORITHMS
from .utils import canonicalize, mime_to_string, mime_to_bytes, quote_as2name, \
    unquote_as2name
from .exceptions import *
from email import utils as email_utils
from email import message as email_message
from email import encoders
from email.mime.multipart import MIMEMultipart
from oscrypto import asymmetric
from oscrypto.errors import SignatureError
from uuid import uuid1
from copy import copy
import logging
import hashlib
import binascii

logger = logging.getLogger('pyas2lib')

AS2_VERSION = '1.2'
EDIINT_FEATURES = 'CMS'

SYNCHRONOUS_MDN = 'SYNC'
ASYNCHRONOUS_MDN = 'ASYNC'

MDN_MODES = (
    SYNCHRONOUS_MDN,
    ASYNCHRONOUS_MDN
)

MDN_CONFIRM_TEXT = 'The AS2 message has been successfully processed. ' \
                   'Thank you for exchanging AS2 messages with pyAS2.'

MDN_FAILED_TEXT = 'The AS2 message could not be processed. The ' \
                  'disposition-notification report has additional details.'


class Organization(object):
    """Class represents an AS2 organization and defines the certificates and
    settings to be used when sending and receiving messages. """

    def __init__(self, as2_id, sign_key=None, sign_key_pass=None,
                 decrypt_key=None, decrypt_key_pass=None, mdn_url=None,
                 mdn_confirm_text=MDN_CONFIRM_TEXT):
        """
        :param as2_id: The unique AS2 name for this organization

        :param sign_key: A byte string of the pkcs12 encoded key pair
            used for signing outbound messages and MDNs.

        :param sign_key_pass: The password for decrypting the `sign_key`

        :param decrypt_key:  A byte string of the pkcs12 encoded key pair
            used for decrypting inbound messages.

        :param decrypt_key_pass: The password for decrypting the `decrypt_key`

        :param mdn_url: The URL where the receiver is expected to post
            asynchronous MDNs.
        """

        # TODO: Need to give option to include CA certificates
        if sign_key:
            self.sign_key = asymmetric.load_pkcs12(
                sign_key, byte_cls(sign_key_pass))
        else:
            self.sign_key = None
        self.decrypt_key = asymmetric.load_pkcs12(
            decrypt_key, byte_cls(decrypt_key_pass)) if decrypt_key else None

        # TODO: Need to verify the certificate here.

        self.as2_id = as2_id
        self.mdn_url = mdn_url
        self.mdn_confirm_text = mdn_confirm_text


class Partner(object):
    """Class represents an AS2 partner and defines the certificates and
    settings to be used when sending and receiving messages."""

    def __init__(self, as2_id, verify_cert=None, encrypt_cert=None,
                 compress=False, sign=False, digest_alg='sha256',
                 encrypt=False, enc_alg='tripledes_192_cbc', mdn_mode=None,
                 mdn_digest_alg=None, mdn_confirm_text=MDN_CONFIRM_TEXT):
        """
        :param as2_id: The unique AS2 name for this partner.

        :param verify_cert: A byte string of the certificate to be used for
            verifying signatures of inbound messages and MDNs.

        :param encrypt_cert: A byte string of the certificate to be used for
            encrypting outbound message.

        :param compress: Set this flag to `True` to compress outgoing
            messages. (default `False`)

        :param sign: Set this flag to `True` to sign outgoing
            messages. (default `False`)

        :param digest_alg: The digest algorithm to be used for generating the
            signature. (default "sha256")

        :param encrypt: Set this flag to `True` to encrypt outgoing
            messages. (default `False`)

        :param enc_alg:
            The encryption algorithm to be used. (default `"tripledes_192_cbc"`)

        :param mdn_mode: The mode to be used for receiving the MDN.
            Set to `None` for no MDN, `'SYNC'` for synchronous and `'ASYNC'`
            for asynchronous. (default `None`)

        :param mdn_digest_alg: The digest algorithm to be used by the receiver
            for signing the MDN. Use `None` for unsigned MDN. (default `None`)

        :param mdn_confirm_text: The text to be used in the MDN for successfully
            processed messages received from this partner.

       """

        # Validations
        if digest_alg not in DIGEST_ALGORITHMS:
            raise ImproperlyConfigured(
                'Unsupported Digest Algorithm {}, must be '
                'one of {}'.format(digest_alg, DIGEST_ALGORITHMS))

        if enc_alg not in ENCRYPTION_ALGORITHMS:
            raise ImproperlyConfigured(
                'Unsupported Encryption Algorithm {}, must be '
                'one of {}'.format(enc_alg, ENCRYPTION_ALGORITHMS))

        if mdn_mode and mdn_mode not in MDN_MODES:
            raise ImproperlyConfigured(
                'Unsupported MDN Mode {}, must be '
                'one of {}'.format(digest_alg, MDN_MODES))

        # if mdn_mode == 'ASYNC' and not mdn_url:
        #     raise ImproperlyConfigured(
        #         'mdn_url is mandatory when mdn_mode is set to ASYNC ')

        if mdn_digest_alg and mdn_digest_alg not in DIGEST_ALGORITHMS:
            raise ImproperlyConfigured(
                'Unsupported MDN Digest Algorithm {}, must be '
                'one of {}'.format(mdn_digest_alg, DIGEST_ALGORITHMS))

        # TODO: Need to give option to include CA certificates

        self.verify_cert = asymmetric.load_certificate(
            verify_cert) if verify_cert else None
        self.encrypt_cert = asymmetric.load_certificate(
            encrypt_cert) if encrypt_cert else None

        # TODO: Need to verify the certificate here.
        self.as2_id = as2_id
        self.compress = compress
        self.sign = sign
        self.digest_alg = digest_alg
        self.encrypt = encrypt
        self.enc_alg = enc_alg
        self.mdn_mode = mdn_mode
        self.mdn_digest_alg = mdn_digest_alg
        self.mdn_confirm_text = mdn_confirm_text


class Message(object):
    """Class for handling AS2 messages. Includes functions for both
    parsing and building messages.
    """

    def __init__(self, sender=None, receiver=None):
        """
        :param sender:
            An object of type <pyas2lib.as2.Organization>, representing the
            sender of the message.

        :param receiver:
            An object of type <pyas2lib.as2.Partner>, representing the
            receiver of the message .
        """
        self.sender = sender
        self.receiver = receiver
        self.compress = False
        self.sign = False
        self.digest_alg = None
        self.encrypt = False
        self.enc_alg = None
        self.message_id = None
        # self.headers = {}
        self.payload = None
        self.mic = None

    @property
    def body(self):
        """Function returns the body of the email message or
        multipart object"""

        if not self.payload:
            return ''

        if self.payload.is_multipart():
            message_bytes = mime_to_bytes(
                self.payload, 0).replace(b'\n', b'\r\n')
            boundary = b'--' + self.payload.get_boundary().encode('utf-8')
            temp = message_bytes.split(boundary)
            temp.pop(0)
            return boundary + boundary.join(temp)
        else:
            new_payload = copy(self.payload)
            for key in new_payload.keys():
                del new_payload[key]
            return mime_to_bytes(new_payload, 0).lstrip()

    @property
    def headers(self):
        if self.payload:
            body = self.body
            return dict(self.payload.items())
        else:
            return {}

    @property
    def headers_str(self):
        message_header = ''
        if self.payload:
            for k, v in self.headers.items():
                message_header += '{}: {}\r\n'.format(k, v)
        return message_header.encode('utf-8')

    def build(self, data, filename=None, subject='AS2 Message',
              content_type='application/edi-consent', additional_headers=None):

        """Function builds the AS2 message. Compresses, signs and encrypts
        the payload if applicable.

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

        """

        # Validations
        assert isinstance(self.sender, Organization), \
            'Parameter sender must be of type {}'.format(Organization)
        assert isinstance(self.receiver, Partner), \
            'Parameter receiver must be of type {}'.format(Partner)
        assert type(data) is byte_cls, \
            'Parameter data must be of type {}'.format(byte_cls)
        additional_headers = additional_headers if additional_headers else {}
        assert type(additional_headers) is dict

        if self.sign and not self.sender.sign_key:
            raise ImproperlyConfigured(
                'Signing of messages is enabled but sign key is not set '
                'for the sender.')

        if self.encrypt and not self.receiver.encrypt_cert:
            raise ImproperlyConfigured(
                'Encryption of messages is enabled but encrypt key is not set '
                'for the receiver.')

        # Generate message id using UUID 1 as it uses both hostname and time
        self.message_id = str(uuid1())

        # Set up the message headers
        as2_headers = {
            'AS2-Version': AS2_VERSION,
            'ediint-features': EDIINT_FEATURES,
            'Message-ID': '<{}>'.format(self.message_id),
            'AS2-From': quote_as2name(self.sender.as2_id),
            'AS2-To': quote_as2name(self.receiver.as2_id),
            'Subject': subject,
            'Date': email_utils.formatdate(localtime=True),
            # 'recipient-address': message.partner.target_url,
        }
        as2_headers.update(additional_headers)

        # Read the input and convert to bytes if value is unicode/str
        # using utf-8 encoding and finally Canonicalize the payload
        self.payload = email_message.Message()
        self.payload.set_payload(data)
        self.payload.set_type(content_type)
        encoders.encode_7or8bit(self.payload)

        # self.payload.add_header('Content-Transfer-Encoding', '8bit')

        if filename:
            self.payload.add_header(
                'Content-Disposition', 'attachment', filename=filename)
        del self.payload['MIME-Version']

        if self.receiver.compress:
            self.compress = True
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

        if self.receiver.sign:
            self.sign, self.digest_alg = True, self.receiver.digest_alg
            signed_message = MIMEMultipart(
                'signed', protocol="application/pkcs7-signature")
            del signed_message['MIME-Version']
            signed_message.attach(self.payload)

            # Calculate the MIC Hash of the message to be verified
            mic_content = canonicalize(self.payload)
            digest_func = hashlib.new(self.digest_alg)
            digest_func.update(mic_content)
            self.mic = binascii.b2a_base64(digest_func.digest()).strip()

            # Create the signature mime message
            signature = email_message.Message()
            signature.set_type('application/pkcs7-signature')
            signature.set_param('name', 'smime.p7s')
            signature.set_param('smime-type', 'signed-data')
            signature.add_header(
                'Content-Disposition', 'attachment', filename='smime.p7s')
            del signature['MIME-Version']
            signature.set_payload(sign_message(
                mic_content, self.digest_alg, self.sender.sign_key))
            encoders.encode_base64(signature)
            signed_message.set_param('micalg', self.digest_alg)
            signed_message.attach(signature)
            self.payload = signed_message

        if self.receiver.encrypt:
            self.encrypt, self.enc_alg = True, self.receiver.enc_alg
            encrypted_message = email_message.Message()
            encrypted_message.set_type('application/pkcs7-mime')
            encrypted_message.set_param('name', 'smime.p7m')
            encrypted_message.set_param('smime-type', 'enveloped-data')
            encrypted_message.add_header(
                'Content-Disposition', 'attachment', filename='smime.p7m')
            encrypted_message.set_payload(encrypt_message(
                canonicalize(self.payload),
                self.enc_alg,
                self.receiver.encrypt_cert
            ))
            encoders.encode_base64(encrypted_message)
            self.payload = encrypted_message

        if self.receiver.mdn_mode:
            as2_headers['disposition-notification-to'] = 'no-reply@pyas2.com'
            if self.receiver.mdn_digest_alg:
                as2_headers['disposition-notification-options'] = \
                    'signed-receipt-protocol=required, pkcs7-signature; ' \
                    'signed-receipt-micalg=optional, {}'.format(
                        self.receiver.mdn_digest_alg)
            if self.receiver.mdn_mode == 'ASYNC':
                if not self.sender.mdn_url:
                    raise ImproperlyConfigured(
                        'MDN URL must be set in the organization when MDN mode '
                        'is set to ASYNC')
                as2_headers['receipt-delivery-option'] = self.sender.mdn_url

        # Update the headers of the final payload
        for k, v in as2_headers.items():
            if self.payload.get(k):
                self.payload.replace_header(k, v)
            else:
                self.payload.add_header(k, v)

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
            A three element tuple containing (status, exception, mdn). The
            status is a string indicating the status of the transaction. The
            exception is populated with any exception raised during processing
            and the mdn is an MDN object or None in case the partner did not
            request it.
        """

        # Parse the raw MIME message and extract its content and headers
        status, exception, mdn = 'processed', None, None
        self.payload = parse_mime(raw_content)
        as2_headers = {}
        for k, v in self.payload.items():
            k = k.lower()
            if k == 'message-id':
                self.message_id = v.lstrip('<').rstrip('>')
            as2_headers[k] = v

        # Get the organization and partner for this transmission
        self.receiver = find_org_cb(unquote_as2name(as2_headers['as2-to']))
        self.sender = find_partner_cb(unquote_as2name(as2_headers['as2-from']))

        if self.sender.encrypt and \
                self.payload.get_content_type() != 'application/pkcs7-mime':
            raise InsufficientSecurityError(
                'Incoming messages from partner {} are defined to be encrypted '
                'but encrypted message not found.'.format(self.receiver.as2_id))

        if self.payload.get_content_type() == 'application/pkcs7-mime' \
                and self.payload.get_param('smime-type') == 'enveloped-data':
            self.encrypt = True
            self.enc_alg, decrypted_content = decrypt_message(
                self.payload.get_payload(decode=True),
                self.receiver.decrypt_key
            )
            raw_content = decrypted_content
            self.payload = parse_mime(decrypted_content)

            if self.payload.get_content_type() == 'text/plain':
                self.payload = email_message.Message()
                self.payload.set_payload(decrypted_content)
                self.payload.set_type('application/edi-consent')

        if self.sender.sign and \
                self.payload.get_content_type() != 'multipart/signed':
            raise InsufficientSecurityError(
                'Incoming messages from partner {} are defined to be signed '
                'but signed message not found.'.format(self.receiver.as2_id))

        if self.payload.get_content_type() == 'multipart/signed':
            self.sign = True
            signature = None
            message_boundary = ('--' + self.payload.get_boundary()).encode('utf-8')
            for part in self.payload.walk():
                if part.get_content_type() == "application/pkcs7-signature":
                    signature = part.get_payload(decode=True)
                else:
                    self.payload = part

            # Verify the message, first using raw message and if it fails
            # then convert to canonical form and try again
            mic_content = canonicalize(self.payload)
            try:
                self.digest_alg = verify_message(
                    mic_content, signature, self.sender.verify_cert)
            except (SignatureError, DigestError):
                mic_content = raw_content.split(message_boundary)[1]
                self.digest_alg = verify_message(
                    mic_content, signature, self.sender.verify_cert)

            # Calculate the MIC Hash of the message to be verified
            digest_func = hashlib.new(self.digest_alg)
            digest_func.update(mic_content)
            self.mic = binascii.b2a_base64(digest_func.digest()).strip()

        if self.payload.get_content_type() == 'application/pkcs7-mime' \
                and self.payload.get_param('smime-type') == 'compressed-data':
            self.compress = True
            decompressed_data = decompress_message(
                self.payload.get_payload(decode=True))
            self.payload = parse_mime(decompressed_data)

        # Update the payload headers with the original headers
        for k, v in as2_headers.items():
            if self.payload.get(k):
                self.payload.replace_header(k, v)
            else:
                self.payload.add_header(k, v)

        if as2_headers.get('disposition-notification-to'):
            mdn_mode = SYNCHRONOUS_MDN

            mdn_url = as2_headers.get('receipt-delivery-option')
            if mdn_url:
                mdn_mode = ASYNCHRONOUS_MDN

            digest_alg = as2_headers.get('disposition-notification-options')
            if digest_alg:
                digest_alg = digest_alg.split(';')[-1].split(',')[-1].strip()

            mdn = MDN(mdn_mode=mdn_mode, mdn_url=mdn_url, digest_alg=digest_alg)
            mdn.build(message=self, status=status)

        return status, exception, mdn


class MDN(object):
    """Class for handling AS2 MDNs. Includes functions for both
    parsing and building them.
    """

    def __init__(self, mdn_mode=None, digest_alg=None, mdn_url=None):
        self.message_id = None
        # self.headers = {}
        self.payload = None
        self.mdn_mode = mdn_mode
        self.digest_alg = digest_alg
        self.mdn_url = mdn_url

    @property
    def body(self):
        """Function returns the body of the email message or
        multipart object"""

        if self.payload:
            message_bytes = mime_to_bytes(
                self.payload, 0).replace(b'\n', b'\r\n')
            boundary = b'--' + self.payload.get_boundary().encode('utf-8')
            temp = message_bytes.split(boundary)
            temp.pop(0)
            return boundary + boundary.join(temp)
        else:
            return ''

    @property
    def headers(self):
        if self.payload:
            body = self.body
            return dict(self.payload.items())
        else:
            return {}

    @property
    def headers_str(self):
        message_header = ''
        if self.payload:
            for k, v in self.headers.items():
                message_header += '{}: {}\r\n'.format(k, v)
        return message_header.encode('utf-8')

    def build(self, message, status, detailed_status=None):

        # Generate message id using UUID 1 as it uses both hostname and time
        self.message_id = str(uuid1())

        # Set up the message headers
        mdn_headers = {
            'AS2-Version': AS2_VERSION,
            'ediint-features': EDIINT_FEATURES,
            'Message-ID': '<{}>'.format(self.message_id),
            'AS2-From': quote_as2name(message.headers.get('as2-to')),
            'AS2-To': quote_as2name(message.headers.get('as2-from')),
            'Date': email_utils.formatdate(localtime=True),
            'user-agent': 'pyAS2 Open Source AS2 Software'
        }

        # Set the confirmation text message here
        confirmation_text = MDN_CONFIRM_TEXT

        # overwrite with organization specific message
        if message.receiver and message.receiver.mdn_confirm_text:
            confirmation_text = message.receiver.mdn_confirm_text

        # overwrite with partner specific message
        if message.sender and message.sender.mdn_confirm_text:
            confirmation_text = message.sender.mdn_confirm_text

        if status != 'processed':
            confirmation_text = MDN_FAILED_TEXT

        self.payload = MIMEMultipart(
            'report', report_type='disposition-notification')

        # Create and attache the MDN Text Message
        mdn_text = email_message.Message()
        mdn_text.set_payload('%s\n' % confirmation_text)
        mdn_text.set_type('text/plain')
        del mdn_text['MIME-Version']
        encoders.encode_7or8bit(mdn_text)
        self.payload.attach(mdn_text)

        # Create and attache the MDN Report Message
        mdn_base = email_message.Message()
        mdn_base.set_type('message/disposition-notification')
        mdn_report = 'Reporting-UA: pyAS2 Open Source AS2 Software\n'
        mdn_report += 'Original-Recipient: rfc822; {}\n'.format(
            message.headers.get('as2-to'))
        mdn_report += 'Final-Recipient: rfc822; {}\n'.format(
            message.headers.get('as2-to'))
        mdn_report += 'Original-Message-ID: <{}>\n'.format(message.message_id)
        mdn_report += 'Disposition: automatic-action/' \
                      'MDN-sent-automatically; {}'.format(status)
        if detailed_status:
            mdn_report += ': {}'.format(detailed_status)
        mdn_report += '\n'
        if message.mic:
            mdn_report += 'Received-content-MIC: {}, {}\n'.format(
                message.mic.decode(), message.digest_alg)
        mdn_base.set_payload(mdn_report)
        del mdn_base['MIME-Version']
        encoders.encode_7or8bit(mdn_base)
        self.payload.attach(mdn_base)

        # Sign the MDN if it is requested by the sender
        if message.headers.get('disposition-notification-options') and \
                message.receiver and message.receiver.sign_key:
            self.digest_alg = \
                message.headers['disposition-notification-options'].split(
                    ';')[-1].split(',')[-1].strip()
            signed_mdn = MIMEMultipart(
                'signed', protocol="application/pkcs7-signature")
            del signed_mdn['MIME-Version']
            signed_mdn.attach(self.payload)

            # Create the signature mime message
            signature = email_message.Message()
            signature.set_type('application/pkcs7-signature')
            signature.set_param('name', 'smime.p7s')
            signature.set_param('smime-type', 'signed-data')
            signature.add_header(
                'Content-Disposition', 'attachment', filename='smime.p7s')
            del signature['MIME-Version']
            signature.set_payload(sign_message(
                canonicalize(self.payload),
                self.digest_alg,
                message.receiver.sign_key
            ))
            encoders.encode_base64(signature)
            signed_mdn.set_param('micalg', self.digest_alg)
            signed_mdn.attach(signature)

            self.payload = signed_mdn

        # Update the headers of the final payload
        for k, v in mdn_headers.items():
            if self.payload.get(k):
                self.payload.replace_header(k, v)
            else:
                self.payload.add_header(k, v)

    def parse(self, raw_content, find_message_cb):
        status, detailed_status = None, None
        self.payload = parse_mime(raw_content)
        orig_message_id, orig_recipient = self.detect_mdn()

        # Call the find message callback which should return a Message instance
        orig_message = find_message_cb(orig_message_id, orig_recipient)

        # Extract the headers and save it
        mdn_headers = {}
        for k, v in self.payload.items():
            k = k.lower()
            if k == 'message-id':
                self.message_id = v.lstrip('<').rstrip('>')
            mdn_headers[k] = v

        if orig_message.receiver.mdn_digest_alg \
                and self.payload.get_content_type() != 'multipart/signed':
            status = 'failed/Failure'
            detailed_status = 'Expected signed MDN but unsigned MDN returned'
            return status, detailed_status

        if self.payload.get_content_type() == 'multipart/signed':
            signature = None
            message_boundary = ('--' + self.payload.get_boundary()).encode('utf-8')
            for part in self.payload.walk():
                if part.get_content_type() == 'application/pkcs7-signature':
                    signature = part.get_payload(decode=True)
                elif part.get_content_type() == 'multipart/report':
                    self.payload = part

            # Verify the message, first using raw message and if it fails
            # then convert to canonical form and try again
            mic_content = raw_content.split(
                message_boundary)[1].strip() + b'\r\n'
            try:
                self.digest_alg = verify_message(
                    mic_content, signature, orig_message.receiver.verify_cert)
            except (SignatureError, DigestError):
                mic_content = canonicalize(self.payload)
                self.digest_alg = verify_message(
                    mic_content, signature, orig_message.receiver.verify_cert)

        for part in self.payload.walk():
            if part.get_content_type() == 'message/disposition-notification':
                mdn = part.get_payload().pop()
                mdn_status = mdn['Disposition'].split(
                    ';').pop().strip().split(':')
                status = mdn_status[0]
                if status == 'processed':
                    mdn_mic = mdn.get('Received-Content-MIC', '').split(',')[0]

                    # TODO: Check MIC for all cases
                    if mdn_mic and orig_message.mic \
                            and mdn_mic != orig_message.mic.decode():
                        status = 'processed/warning'
                        detailed_status = 'Message Integrity check failed.'
                else:
                    detailed_status = ' '.join(mdn_status[1:])

        return status, detailed_status

    def detect_mdn(self):
        mdn_message = None
        if self.payload.get_content_type() == 'multipart/report':
            mdn_message = self.payload
        elif self.payload.get_content_type() == 'multipart/signed':
            for part in self.payload.walk():
                if part.get_content_type() == 'multipart/report':
                    mdn_message = self.payload

        if not mdn_message:
            raise MDNNotFound('No MDN found in the received message')

        message_id, message_recipient = None, None
        for part in mdn_message.walk():
            if part.get_content_type() == 'message/disposition-notification':
                mdn = part.get_payload()[0]
                message_id = mdn.get('Original-Message-ID')
                message_recipient = mdn.get('Original-Recipient').split(';')[1]
        return message_id, message_recipient
