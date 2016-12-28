from __future__ import absolute_import
from __future__ import unicode_literals
from .compat import str_cls, byte_cls, parse_mime
from .cms import compress_message, decompress_message, decrypt_message, \
    encrypt_message, verify_message
from .utils import canonicalize, mime_to_string, mime_to_bytes
from email import utils as email_utils
from email import message as email_message
from email import encoders
from oscrypto import asymmetric
from asn1crypto import pem, x509
from uuid import uuid1
from os.path import basename
from .exceptions import *
import logging

logger = logging.getLogger('pyas2lib')


class Organization(object):

    def __init__(self, as2_id, sign_key=None, sign_key_pass=None,
                 decrypt_key=None, decrypt_key_pass=None):
        self.as2_id = as2_id

        # TODO: Need to give option to include CA certificates
        self.sign_key = asymmetric.load_private_key(
            sign_key, sign_key_pass) if sign_key else None
        self.decrypt_key = asymmetric.load_private_key(
            decrypt_key, decrypt_key_pass) if decrypt_key else None


class Partner(object):

    def __init__(self, as2_id, verify_cert=None, encrypt_cert=None,
                 indefinite_length=False):
        self.as2_id = as2_id

        # TODO: Need to give option to include CA certificates
        self.verify_cert = Partner.load_cert(
            verify_cert) if verify_cert else None
        self.encrypt_cert = Partner.load_cert(
            encrypt_cert) if encrypt_cert else None
        self.indefinite_length = indefinite_length

    @staticmethod
    def load_cert(path_to_cert):
        with open(path_to_cert, 'rb') as f:
            der_bytes = f.read()
            if pem.detect(der_bytes):
                type_name, headers, der_bytes = pem.unarmor(der_bytes)

        return x509.Certificate.load(der_bytes)


class Message(object):
    """Class for handling AS2 messages. Includes functions for both
    parsing and building messages.

    """

    _AS2_VERSION = '1.2'
    _MIME_VERSION = '1.0'
    _EDIINT_FEATURES = 'CMS'
    _DIGEST_ALGORITHMS = (
        'md5',
        'sha1',
        'sha256',
        'sha512'
    )
    _ENCRYPTION_ALGORITHMS = (
        'tripledes_192_cbc',
        'rc2_128_cbc',
        'rc4_128_cbc',
        'aes_128_cbc',
        'aes_192_cbc',
        'aes_256_cbc',
    )

    def __init__(self, compress=False, sign=False, digest_alg='sha256',
                 encrypt=False, enc_alg='tripledes_192_cbc', mdn_mode=None,
                 mdn_url=None):
        self.compress = compress
        self.sign = sign
        self.digest_alg = digest_alg
        self.encrypt = encrypt
        self.enc_alg = enc_alg
        self.mdn_mode = mdn_mode
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

    def build(self, organization, partner, fp, encoding='utf-8',
              subject='AS2 Message', content_type='application/edi-consent'):

        # Initial assertions
        assert type(organization) is Organization
        assert type(partner) is Partner

        # Generate message id using UUID 1 as it uses both hostname and time
        self.message_id = str(uuid1())

        # Set up the message headers
        self.headers = {
            'AS2-Version': Message._AS2_VERSION,
            'ediint-features': Message._EDIINT_FEATURES,
            'MIME-Version': Message._MIME_VERSION,
            'Message-ID': '<{}>'.format(self.message_id),
            'AS2-From': organization.as2_id,
            'AS2-To': partner.as2_id,
            'Subject': subject,
            'Date': email_utils.formatdate(localtime=True),
            # 'recipient-address': message.partner.target_url,
        }

        # Read the input and convert to bytes if value is unicode/str
        # using utf-8 encoding and finally Canonicalize the payload
        mic_content = None
        file_content = fp.read()
        if type(file_content) == str_cls:
            file_content = file_content.encode('utf-8')
        self.payload = email_message.Message()
        self.payload.set_payload(file_content)
        self.payload.set_type(content_type)

            # mime_to_string(self.payload, 0)

        if hasattr(fp, 'name'):
            self.payload.add_header(
                'Content-Disposition', 'attachment', filename=basename(fp.name))
        del self.payload['MIME-Version']

        if self.compress:
            compressed_message = email_message.Message()
            compressed_message.set_type('application/pkcs7-mime')
            compressed_message.set_param('name', 'smime.p7z')
            compressed_message.set_param('smime-type', 'compressed-data')
            compressed_message.add_header('Content-Disposition', 'attachment',
                                          filename='smime.p7z')
            compressed_payload = compress_message(
                mime_to_string(self.payload, 0)).dump()
            compressed_message.set_payload(compressed_payload)
            encoders.encode_base64(compressed_message)
            self.payload = compressed_message

        if self.sign:
            pass

        if self.encrypt:
            encrypted_message = email_message.Message()
            encrypted_message.set_type('application/pkcs7-mime')
            encrypted_message.set_param('name', 'smime.p7m')
            encrypted_message.set_param('smime-type', 'enveloped-data')
            encrypted_message.add_header(
                'Content-Disposition', 'attachment', filename='smime.p7m')
            encrypted_payload = encrypt_message(
                mime_to_string(self.payload, 0),
                self.enc_alg,
                partner.encrypt_cert
            ).dump()
            encrypted_message.set_payload(encrypted_payload)
            encoders.encode_base64(encrypted_message)
            self.payload = encrypted_message

        if self.mdn_mode:
            pass

        return mic_content

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
            The MIC Content of the received message to be used while generating
            the MDN.
        """

        # Parse the raw MIME message and extract its content and headers
        self.payload = parse_mime(raw_content)
        mic_content = None
        for k, v in self.payload.items():
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
                # if filename:
                #     payload.add_header('Content-Disposition', 'attachment',
                #                        filename=filename)

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
            mic_content = mime_to_string(self.payload, 0)
            self.digest_alg = verify_message(
                mic_content,
                signature,
                partner.verify_cert
            )

        if self.payload.get_content_type() == 'application/pkcs7-mime' \
                and self.payload.get_param('smime-type') == 'compressed-data':
            self.compress = True
            decompressed_data = decompress_message(
                self.payload.get_payload(decode=True),
                partner.indefinite_length
            )
            self.payload = parse_mime(decompressed_data)

        return mic_content
