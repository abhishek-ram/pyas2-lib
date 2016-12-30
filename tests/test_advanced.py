from __future__ import unicode_literals, absolute_import, print_function
from .context import as2
import unittest
import os

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata')


class TestAdvanced(unittest.TestCase):

    def setUp(self):
        self.test_file = open(
                os.path.join(TEST_DIR, 'payload.txt'), 'rb')
        with open(os.path.join(TEST_DIR, 'cert_test.p12'), 'rb') as key_file:
            key = key_file.read()
            self.org = as2.Organization(
                as2_id='some_organization',
                sign_key=key,
                sign_key_pass='test'.encode('utf-8'),
                decrypt_key=key,
                decrypt_key_pass='test'.encode('utf-8')
            )
        with open(os.path.join(TEST_DIR, 'cert_test_public.pem'), 'rb') as cert_file:
            cert = cert_file.read()
            self.partner = as2.Partner(
                as2_id='some_partner',
                verify_cert=cert,
                encrypt_cert=cert,
            )

    def tearDown(self):
        self.test_file.close()

    def test_binary_message(self):
        """ Test Encrypted Signed Binary Message """

        # Build an As2 message to be transmitted to partner
        out_message = as2.Message(sign=True, encrypt=True, compress=True)
        with open(os.path.join(TEST_DIR, 'payload.binary'), 'rb') as bin_file:
            original_message = bin_file.read()
            out_mic_content = out_message.build(
                self.org,
                self.partner,
                original_message,
                filename='payload.binary',
                content_type='application/octet-stream'
            )
        raw_out_message = bytes(out_message)

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        in_mic_content = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner
        )

        # Compare the mic contents of the input and output messages
        # self.assertEqual(original_message,
        #                  in_message.payload.get_payload(decode=True))
        self.assertTrue(in_message.sign)
        self.assertTrue(in_message.encrypt)
        self.assertEqual(out_mic_content, in_mic_content)

    def find_org(self, headers):
        return self.org

    def find_partner(self, headers):
        return self.partner
