"""Module for testing the MDN related features of pyas2lib"""
import socket
from pyas2lib import as2
from . import Pyas2TestCase


class TestMDN(Pyas2TestCase):
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
        self.out_message = None

    def test_unsigned_mdn(self):
        """Test unsigned MDN generation and parsing"""

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.mdn_mode = as2.SYNCHRONOUS_MDN
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        # Parse the generated AS2 message as the partner
        raw_out_message = (
            self.out_message.headers_str + b"\r\n" + self.out_message.content
        )
        in_message = as2.Message()
        _, _, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
        )

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b"\r\n" + mdn.content, find_message_cb=self.find_message
        )

        self.assertEqual(status, "processed")

    def test_signed_mdn(self):
        """Test signed MDN generation and parsing"""

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.mdn_mode = as2.SYNCHRONOUS_MDN
        self.partner.mdn_digest_alg = "sha256"
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        # Parse the generated AS2 message as the partner
        raw_out_message = (
            self.out_message.headers_str + b"\r\n" + self.out_message.content
        )
        in_message = as2.Message()
        _, _, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
        )

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b"\r\n" + mdn.content, find_message_cb=self.find_message
        )
        self.assertEqual(status, "processed")

    def test_failed_mdn_parse(self):
        """Test mdn parsing failures are captured."""
        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.mdn_mode = as2.SYNCHRONOUS_MDN
        self.partner.mdn_digest_alg = "sha256"
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        # Parse the generated AS2 message as the partner
        raw_out_message = (
            self.out_message.headers_str + b"\r\n" + self.out_message.content
        )
        in_message = as2.Message()
        _, _, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
        )

        out_mdn = as2.Mdn()
        self.partner.verify_cert = self.mecas2_public_key
        self.partner.validate_certs = False
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b"\r\n" + mdn.content, find_message_cb=self.find_message
        )
        self.assertEqual(status, "failed/Failure")
        self.assertEqual(
            detailed_status,
            "Failed to parse received MDN. Failed to verify message signature: "
            "Message Digest does not match.",
        )

    def test_mdn_with_domain(self):
        """Test MDN generation with an org domain"""
        self.org.domain = "example.com"

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.mdn_mode = as2.SYNCHRONOUS_MDN
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        # Parse the generated AS2 message as the partner
        raw_out_message = (
            self.out_message.headers_str + b"\r\n" + self.out_message.content
        )
        in_message = as2.Message()
        _, _, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
        )

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b"\r\n" + mdn.content, find_message_cb=self.find_message
        )

        self.assertEqual(out_mdn.message_id.split("@")[1], self.org.domain)

    def test_mdn_without_domain(self):
        """Test MDN generation without an org domain"""

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.mdn_mode = as2.SYNCHRONOUS_MDN
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        # Parse the generated AS2 message as the partner
        raw_out_message = (
            self.out_message.headers_str + b"\r\n" + self.out_message.content
        )
        in_message = as2.Message()
        _, _, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
        )

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b"\r\n" + mdn.content, find_message_cb=self.find_message
        )

        self.assertEqual(out_mdn.message_id.split("@")[1], socket.getfqdn())

    def find_org(self, as2_id):
        return self.org

    def find_partner(self, as2_id):
        return self.partner

    def find_message(self, message_id, message_recipient):
        return self.out_message
