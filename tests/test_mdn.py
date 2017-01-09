from __future__ import unicode_literals, absolute_import, print_function
from .context import as2
import unittest
import os

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata')


class TestMDN(unittest.TestCase):

    def setUp(self):
        self.test_file = open(os.path.join(TEST_DIR, 'payload.txt'), 'rb')
        with open(os.path.join(TEST_DIR, 'cert_test.p12'), 'rb') as key_file:
            key = key_file.read()
            self.org = as2.Organization(
                as2_id='some_organization',
                sign_key=key,
                sign_key_pass='test'.encode('utf-8'),
                decrypt_key=key,
                decrypt_key_pass='test'.encode('utf-8')
            )
        with open(os.path.join(
                TEST_DIR, 'cert_test_public.pem'), 'rb') as cert_file:
            cert = cert_file.read()
            self.partner = as2.Partner(
                as2_id='some_partner',
                verify_cert=cert,
                encrypt_cert=cert,
            )
        self.out_message = None

    def tearDown(self):
        self.test_file.close()

    def test_unsigned_mdn(self):
        """ Test unsigned MDN generation and parsing """

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.mdn_mode = as2.SYNCHRONOUS_MDN
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_file.read())

        # Parse the generated AS2 message as the partner
        raw_out_message = \
            self.out_message.headers_str + b'\r\n' + self.out_message.body
        in_message = as2.Message()
        _, _, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner
        )

        out_mdn = as2.MDN()
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b'\r\n' + mdn.body,
            find_message_cb=self.find_message
        )

        self.assertEqual(status, 'processed')

    def test_signed_mdn(self):
        """ Test signed MDN generation and parsing """

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.mdn_mode = as2.SYNCHRONOUS_MDN
        self.partner.mdn_digest_alg = 'sha256'
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_file.read())

        # Parse the generated AS2 message as the partner
        raw_out_message = \
            self.out_message.headers_str + b'\r\n' + self.out_message.body
        in_message = as2.Message()
        _, _, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner
        )

        out_mdn = as2.MDN()
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b'\r\n' +mdn.body,
            find_message_cb=self.find_message
        )
        print(bytes(mdn))
        self.assertEqual(status, 'processed')

    def find_org(self, as2_id):
        return self.org

    def find_partner(self, as2_id):
        return self.partner

    def find_message(self, message_id, message_recipient):
        return self.out_message
