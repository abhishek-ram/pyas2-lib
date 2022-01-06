"""Module for testing with a live old pyas2 server."""
import os

import requests

from pyas2lib import as2
from . import Pyas2TestCase

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")


class LiveTestMecAS2(Pyas2TestCase):
    def setUp(self):
        self.org = as2.Organization(
            as2_name="pyas2lib",
            sign_key=self.private_key,
            sign_key_pass="test",
            decrypt_key=self.private_key,
            decrypt_key_pass="test",
        )

        self.partner = as2.Partner(
            as2_name="pyas2idev",
            verify_cert=self.oldpyas2_public_key,
            encrypt_cert=self.oldpyas2_public_key,
            mdn_mode=as2.SYNCHRONOUS_MDN,
            mdn_digest_alg="sha256",
        )
        self.out_message = None

    def test_compressed_message(self):
        """Send Unencrypted Unsigned Compressed  Message to Mendelson AS2"""

        self.partner.compress = True
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        response = requests.post(
            "http://localhost:8080/pyas2/as2receive",
            headers=self.out_message.headers,
            data=self.out_message.content,
        )
        raw_mdn = ""
        for k, v in response.headers.items():
            raw_mdn += "{}: {}\n".format(k, v)

        raw_mdn = raw_mdn + "\n" + response.text

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            raw_mdn, find_message_cb=self.find_message
        )
        self.assertEqual(status, "processed")

    def test_encrypted_message(self):
        """Send Encrypted Unsigned Uncompressed Message to Mendelson AS2"""

        self.partner.encrypt = True
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        response = requests.post(
            "http://localhost:8080/pyas2/as2receive",
            headers=self.out_message.headers,
            data=self.out_message.content,
        )
        raw_mdn = ""
        for k, v in response.headers.items():
            raw_mdn += "{}: {}\n".format(k, v)

        raw_mdn = raw_mdn + "\n" + response.text

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            raw_mdn, find_message_cb=self.find_message
        )
        self.assertEqual(status, "processed")

    def test_signed_message(self):
        """Send Unencrypted Signed Uncompressed Message to Mendelson AS2"""

        self.partner.sign = True
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        response = requests.post(
            "http://localhost:8080/pyas2/as2receive",
            data=self.out_message.content,
            headers=self.out_message.headers,
        )

        raw_mdn = ""
        for k, v in response.headers.items():
            raw_mdn += "{}: {}\n".format(k, v)
        raw_mdn = raw_mdn + "\n" + response.text

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            raw_mdn, find_message_cb=self.find_message
        )
        self.assertEqual(status, "processed")

    def test_encrypted_signed_message(self):
        """Send Encrypted Signed Uncompressed Message to Mendelson AS2"""

        self.partner.sign = True
        self.partner.encrypt = True
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        response = requests.post(
            "http://localhost:8080/pyas2/as2receive",
            data=self.out_message.content,
            headers=self.out_message.headers,
        )

        raw_mdn = ""
        for k, v in response.headers.items():
            raw_mdn += "{}: {}\n".format(k, v)
        raw_mdn = raw_mdn + "\n" + response.text

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            raw_mdn, find_message_cb=self.find_message
        )
        self.assertEqual(status, "processed")

    def test_encrypted_signed_compressed_message(self):
        """Send Encrypted Signed Compressed Message to Mendelson AS2"""

        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.compress = True
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        response = requests.post(
            "http://localhost:8080/pyas2/as2receive",
            data=self.out_message.content,
            headers=self.out_message.headers,
        )

        raw_mdn = ""
        for k, v in response.headers.items():
            raw_mdn += "{}: {}\n".format(k, v)
        raw_mdn = raw_mdn + "\n" + response.text

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            raw_mdn, find_message_cb=self.find_message
        )
        self.assertEqual(status, "processed")

    def find_org(self, headers):
        return self.org

    def find_partner(self, headers):
        return self.partner

    def find_message(self, message_id, message_recipient):
        return self.out_message
