from __future__ import unicode_literals, absolute_import, print_function
from . import PYAS2TestCase, as2
import os

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata')


class TestAdvanced(PYAS2TestCase):

    def setUp(self):
        self.org = as2.Organization(
            as2_id='some_organization',
            sign_key=self.private_key,
            sign_key_pass='test'.encode('utf-8'),
            decrypt_key=self.private_key,
            decrypt_key_pass='test'.encode('utf-8')
        )
        self.partner = as2.Partner(
            as2_id='some_partner',
            verify_cert=self.public_key,
            encrypt_cert=self.public_key,
        )

    def test_binary_message(self):
        """ Test Encrypted Signed Binary Message """

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.compress = True
        out_message = as2.Message(self.org, self.partner)
        with open(os.path.join(
                self.TEST_DIR, 'payload.binary'), 'rb') as bin_file:
            original_message = bin_file.read()
            out_message.build(
                original_message,
                filename='payload.binary',
                content_type='application/octet-stream'
            )
        raw_out_message = out_message.headers_str + b'\r\n' + out_message.content

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
        self.assertEqual(out_message.mic, in_message.mic)

    def find_org(self, headers):
        return self.org

    def find_partner(self, headers):
        return self.partner
