from __future__ import unicode_literals, absolute_import, print_function
from . import as2, Pyas2TestCase


class TestBasicDos(Pyas2TestCase):

    def setUp(self):
        self.org = as2.Organization(
            as2_name='some_organization',
            sign_key=self.private_key,
            sign_key_pass='test'.encode('utf-8'),
            decrypt_key=self.private_key,
            decrypt_key_pass='test'.encode('utf-8')
        )
        self.partner = as2.Partner(
            as2_name='some_partner',
            verify_cert=self.public_key,
            encrypt_cert=self.public_key
        )

    def test_file_is_dos(self):
        self.assertTrue(b'\r\n' in self.test_data_dos)

    def test_plain_message(self):
        """ Test Unencrypted Unsigned Uncompressed Message """

        # Build an As2 message to be transmitted to partner
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data_dos)
        raw_out_message = \
            out_message.headers_str + b'\r\n' + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner
        )

        # Compare contents of the input and output messages
        self.assertEqual(status, 'processed')
        self.assertEqual(self.test_data_dos, in_message.content)

    def test_compressed_message(self):
        """ Test Unencrypted Unsigned Compressed Message """

        # Build an As2 message to be transmitted to partner
        self.partner.compress = True
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data_dos)
        raw_out_message = out_message.headers_str + b'\r\n' + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner
        )

        # Compare the mic contents of the input and output messages
        self.assertEqual(status, 'processed')
        self.assertTrue(in_message.compressed)
        self.assertEqual(self.test_data_dos, in_message.content)

    def test_encrypted_message(self):
        """ Test Encrypted Unsigned Uncompressed Message """

        # Build an As2 message to be transmitted to partner
        self.partner.encrypt = True
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data_dos)
        raw_out_message = out_message.headers_str + b'\r\n' + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner
        )

        # Compare the mic contents of the input and output messages
        self.assertEqual(status, 'processed')
        self.assertTrue(in_message.encrypted)
        self.assertEqual(self.test_data_dos, in_message.content)

    def test_signed_message(self):
        """ Test Unencrypted Signed Uncompressed Message """

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data_dos)
        raw_out_message = out_message.headers_str + b'\r\n' + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner
        )

        # Compare the mic contents of the input and output messages
        self.assertEqual(status, 'processed')
        self.assertEqual(self.test_data_dos, in_message.content)
        self.assertTrue(in_message.signed)
        self.assertEqual(out_message.mic, in_message.mic)

    def test_encrypted_signed_message(self):
        """ Test Encrypted Signed Uncompressed Message """

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data_dos)
        raw_out_message = out_message.headers_str + b'\r\n' + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner
        )

        # Compare the mic contents of the input and output messages
        self.assertEqual(status, 'processed')
        self.assertEqual(self.test_data_dos, in_message.content)
        self.assertTrue(in_message.signed)
        self.assertTrue(in_message.encrypted)
        self.assertEqual(out_message.mic, in_message.mic)

    def test_encrypted_signed_compressed_message(self):
        """ Test Encrypted Signed Compressed Message """

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.compress = True
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data_dos)
        raw_out_message = out_message.headers_str + b'\r\n' + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner
        )

        # Compare the mic contents of the input and output messages
        self.assertEqual(status, 'processed')
        self.assertEqual(self.test_data_dos, in_message.content)
        self.assertTrue(in_message.signed)
        self.assertTrue(in_message.encrypted)
        self.assertTrue(in_message.compressed)
        self.assertEqual(out_message.mic, in_message.mic)

    def find_org(self, as2_id):
        return self.org

    def find_partner(self, as2_id):
        return self.partner
