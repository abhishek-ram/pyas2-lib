from __future__ import absolute_import
from __future__ import unicode_literals
from .compat import StringIO
from email import utils as email_utils
from email import message as email_message
from email import generator as email_generator
from email import message_from_string
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
            fp = StringIO()
            g = email_generator.Generator(
                fp, mangle_from_=False)
            g.flatten(self.payload)
            return fp.getvalue()
        else:
            return ''

    def build(self, organization, partner, fp, subject='AS2 Message',
              content_type='application/edi-consent'):

        mic_content = fp.read()
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

        self.payload = email_message.Message()
        self.payload.set_payload(mic_content)
        self.payload.set_type(content_type)
        if hasattr(fp, 'name'):
            self.payload.add_header('Content-Disposition', 'attachment',
                                    filename=basename(fp.name))
        del self.payload['MIME-Version']

        if self.compress:
            pass

        if self.sign:
            pass

        if self.encrypt:
            pass

        if self.mdn_mode:
            pass

        return mic_content

    def parse(self, raw_content, validate_org_callback=None,
              validate_partner_callback=None):
        self.payload = message_from_string(raw_content)
        mic_content = self.payload.get_payload()
        for k,v in self.payload.items():
            self.headers[k] = v

        if self.encrypt and \
                self.payload.get_content_type() != 'application/pkcs7-mime':
            pass

        if self.payload.get_content_type() == 'application/pkcs7-mime' \
                and self.payload.get_param('smime-type') == 'enveloped-data':
            pass

        if self.sign and \
                self.payload.get_content_type() != 'multipart/signed':
            pass

        if self.payload.get_content_type() == 'multipart/signed':
            pass

        if self.payload.get_content_type() == 'application/pkcs7-mime' \
                and self.payload.get_param('smime-type') == 'compressed-data':
            pass
        return mic_content
