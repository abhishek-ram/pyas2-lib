"""Module for testing the basic features of pyas2."""
import socket
from pyas2lib import as2
from . import Pyas2TestCase


class TestBasic(Pyas2TestCase):
    def setUp(self):
        self.org = as2.Organization(
            as2_name="some_organization",
            sign_key=self.private_key,
            sign_key_pass="test",
            decrypt_key=self.private_key,
            decrypt_key_pass="test",
        )
        self.partner = as2.Partner(
            as2_name="some_partner",
            verify_cert=self.public_key,
            encrypt_cert=self.public_key,
        )

    def test_plain_message(self):
        """Test Unencrypted Unsigned Uncompressed Message"""

        # Build an As2 message to be transmitted to partner
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data)
        raw_out_message = out_message.headers_str + b"\r\n" + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
        )

        # Compare contents of the input and output messages
        self.assertEqual(status, "processed")
        self.assertEqual(self.test_data, in_message.content)

    def test_compressed_message(self):
        """Test Unencrypted Unsigned Compressed Message"""

        # Build an As2 message to be transmitted to partner
        self.partner.compress = True
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data)
        raw_out_message = out_message.headers_str + b"\r\n" + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
        )

        # Compare the mic contents of the input and output messages
        self.assertEqual(status, "processed")
        self.assertTrue(in_message.compressed)
        self.assertEqual(self.test_data.splitlines(), in_message.content.splitlines())

    def test_encrypted_message(self):
        """Test Encrypted Unsigned Uncompressed Message"""

        # Build an As2 message to be transmitted to partner
        self.partner.encrypt = True
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data)
        raw_out_message = out_message.headers_str + b"\r\n" + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
        )

        # Compare the mic contents of the input and output messages
        self.assertEqual(status, "processed")
        self.assertTrue(in_message.encrypted)
        self.assertEqual(self.test_data.splitlines(), in_message.content.splitlines())

    def test_signed_message(self):
        """Test Unencrypted Signed Uncompressed Message"""

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data)
        raw_out_message = out_message.headers_str + b"\r\n" + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
        )

        # Compare the mic contents of the input and output messages
        self.assertEqual(status, "processed")
        self.assertEqual(self.test_data.splitlines(), in_message.content.splitlines())
        self.assertTrue(in_message.signed)
        self.assertEqual(out_message.mic, in_message.mic)

    def test_encrypted_signed_message(self):
        """Test Encrypted Signed Uncompressed Message"""

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data)
        raw_out_message = out_message.headers_str + b"\r\n" + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
        )

        # Compare the mic contents of the input and output messages
        self.assertEqual(status, "processed")
        self.assertTrue(in_message.signed)
        self.assertTrue(in_message.encrypted)
        self.assertEqual(out_message.mic, in_message.mic)
        self.assertEqual(self.test_data.splitlines(), in_message.content.splitlines())

    def test_encrypted_signed_message_dos(self):
        """Test Encrypted Signed Uncompressed Message with DOS line endings."""

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data_dos)
        raw_out_message = out_message.headers_str + b"\r\n" + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
        )

        # Compare the mic contents of the input and output messages
        self.assertEqual(status, "processed")
        self.assertTrue(in_message.signed)
        self.assertTrue(in_message.encrypted)
        self.assertEqual(out_message.mic, in_message.mic)
        self.assertEqual(self.test_data_dos, in_message.content)

    def test_encrypted_signed_compressed_message(self):
        """Test Encrypted Signed Compressed Message"""

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.compress = True
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data)
        raw_out_message = out_message.headers_str + b"\r\n" + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
        )

        # Compare the mic contents of the input and output messages
        self.assertEqual(status, "processed")
        self.assertTrue(in_message.signed)
        self.assertTrue(in_message.encrypted)
        self.assertTrue(in_message.compressed)
        self.assertEqual(out_message.mic, in_message.mic)
        self.assertEqual(self.test_data.splitlines(), in_message.content.splitlines())

    def test_plain_message_with_domain(self):
        """Test Message building with an org domain"""

        # Build an As2 message to be transmitted to partner
        self.org.domain = "example.com"
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data)
        self.assertEqual(out_message.message_id.split("@")[1], self.org.domain)

    def test_plain_message_without_domain(self):
        """Test Message building without an org domain"""

        # Build an As2 message to be transmitted to partner
        out_message = as2.Message(self.org, self.partner)
        out_message.build(self.test_data)
        self.assertEqual(out_message.message_id.split("@")[1], socket.getfqdn())

    def find_org(self, as2_id):
        return self.org

    def find_partner(self, as2_id):
        return self.partner
