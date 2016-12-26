from __future__ import unicode_literals, absolute_import, print_function
from .context import as2
import unittest
import os

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata')


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.test_file = open(
                os.path.join(TEST_DIR, 'payload.txt'), 'rb')
        self.org = as2.Organization(
            as2_id='some_organization',
            sign_key=os.path.join(TEST_DIR, 'cert_test_private.pem'),
            sign_key_pass='test',
            decrypt_key=os.path.join(TEST_DIR, 'cert_test_private.pem'),
            decrypt_key_pass='test'
        )
        self.partner = as2.Partner(
            as2_id='some_partner',
            verify_cert=os.path.join(TEST_DIR, 'cert_test_public.pem'),
            encrypt_cert=os.path.join(TEST_DIR, 'cert_test_public.pem'),
        )

    def tearDown(self):
        self.test_file.close()

    def test_plain_message(self):
        """ Test Unencrypted Unsigned Uncompressed Message """

        # Build an As2 message to be transmitted to partner
        out_message = as2.Message()
        out_message.build(
            'some_organization', 'some_partner', self.test_file)
        raw_out_message = bytes(out_message)

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner
        )

        # Compare the mic contents of the input and output messages
        self.test_file.seek(0)
        original_message = self.test_file.read()
        self.assertEqual(original_message,
                         in_message.payload.get_payload(decode=True))

    def test_compressed_message(self):
        """ Test Unencrypted Unsigned Compressed Message """

        # Build an As2 message to be transmitted to partner
        out_message = as2.Message(compress=True)
        out_mic_content = out_message.build(
            'some_organization', 'some_partner', self.test_file)
        raw_out_message = bytes(out_message)
        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        in_mic_content = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner
        )

        # Compare the mic contents of the input and output messages
        self.assertEqual(out_mic_content, in_mic_content.decode('utf-8'))

    def find_org(self, headers):
        return self.org

    def find_partner(self, headers):
        return self.partner
