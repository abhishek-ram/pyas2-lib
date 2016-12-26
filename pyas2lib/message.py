from __future__ import absolute_import
from __future__ import unicode_literals
from .compat import StringIO, EmailGenerator, str_cls, byte_cls, parse_mime
from .cms import compress_message, decompress_message, decrypt_message
from .utils import canonicalize, mime_to_string, mime_to_bytes
from email import utils as email_utils
from email import message as email_message
from email import message_from_string
from email import encoders 
from uuid import uuid1
from os.path import basename
from .exceptions import *
import logging

logger = logging.getLogger('pyas2lib')


class Message(object):
    """Class for building and parsing AS2 Inbound and Outbound Messages

    """

    _AS2_VERSION = '1.2'
    _MIME_VERSION = '1.0'
    _EDIINT_FEATURES = 'CMS'
    _SIGNATURE_ALGORITHMS = (
        'MD5',
        'SHA1',
        'SHA256',
        'SHA512'
    )
    _ENCRYPTION_ALGORITHMS = (
        '3DES_CBC_168',
    )

    def __init__(self, compress=False, sign=False, sig_alg='SHA256',
                 encrypt=False, enc_alg='3DES_CBC_168', mdn_mode=None,
                 mdn_url=None):
        self.compress = compress
        self.sign = sign
        self.sig_alg = sig_alg
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

        # Generate message id using UUID 1 as it uses both hostname and time
        self.message_id = str(uuid1())

        # Set up the message headers
        self.headers = {
            'AS2-Version': Message._AS2_VERSION,
            'ediint-features': Message._EDIINT_FEATURES,
            'MIME-Version': Message._MIME_VERSION,
            'Message-ID': '<{}>'.format(self.message_id),
            'AS2-From': organization,
            'AS2-To': partner,
            'Subject': subject,
            'Date': email_utils.formatdate(localtime=True),
            # 'recipient-address': message.partner.target_url,
        }

        # Read the input and convert to bytes if value is unicode/str
        # using utf-8 encoding and finally Canonicalize the payload 
        file_content = fp.read()
        if type(file_content) == str_cls:
            file_content = file_content.encode('utf-8')
        self.payload = email_message.Message()
        self.payload.set_payload(file_content)
        self.payload.set_type(content_type)
        mic_content = canonicalize(mime_to_string(self.payload, 0))

        if hasattr(fp, 'name'):
            self.payload.add_header('Content-Disposition', 'attachment',
                                    filename=basename(fp.name))
        del self.payload['MIME-Version']

        if self.compress:
            compressed_message = email_message.Message()
            compressed_message.set_type('application/pkcs7-mime')
            compressed_message.set_param('name', 'smime.p7z')
            compressed_message.set_param('smime-type', 'compressed-data')
            compressed_message.add_header('Content-Disposition', 'attachment',
                                          filename='smime.p7z')
            compressed_payload = compress_message(mic_content.encode(encoding)).dump()
            compressed_message.set_payload(compressed_payload)
            encoders.encode_base64(compressed_message)
            print(compressed_message)
            self.payload = compressed_message

        if self.sign:
            pass

        if self.encrypt:
            pass

        if self.mdn_mode:
            pass

        return mic_content

    def parse(self, raw_content, validate_org_callback=None,
              validate_partner_callback=None, ):
        self.payload = parse_mime(raw_content)
        mic_content = self.payload.get_payload(decode=True)
        for k,v in self.payload.items():
            self.headers[k] = v

        if self.encrypt and \
                self.payload.get_content_type() != 'application/pkcs7-mime':
            pass

        if self.payload.get_content_type() == 'application/pkcs7-mime' \
                and self.payload.get_param('smime-type') == 'enveloped-data':
            self.compress = True
            decrypted_data = mic_content = \
                decrypt_message(mic_content)
            self.payload = parse_mime(decrypted_data)

        if self.sign and \
                self.payload.get_content_type() != 'multipart/signed':
            pass

        if self.payload.get_content_type() == 'multipart/signed':
            pass

        if self.payload.get_content_type() == 'application/pkcs7-mime' \
                and self.payload.get_param('smime-type') == 'compressed-data':
            self.compress = True
            decompressed_data = mic_content = \
                decompress_message(mic_content)
            self.payload = parse_mime(decompressed_data)
        return mic_content
