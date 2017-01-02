from __future__ import unicode_literals, absolute_import, print_function
from .context import as2, exceptions
import unittest
import os

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata')


class TestMecAS2(unittest.TestCase):

    def setUp(self):
        self.test_file = open(
                os.path.join(TEST_DIR, 'payload.txt'))
        with open(os.path.join(TEST_DIR, 'cert_test.p12'), 'rb') as key_file:
            key = key_file.read()
            self.org = as2.Organization(
                as2_id='some_organization',
                sign_key=key,
                sign_key_pass='test'.encode('utf-8'),
                decrypt_key=key,
                decrypt_key_pass='test'.encode('utf-8')
            )
        with open(os.path.join(TEST_DIR, 'cert_mecas2_public.pem'), 'rb') as c_file:
            cert = c_file.read()
            self.partner = as2.Partner(
                as2_id='mecas2',
                verify_cert=cert,
                encrypt_cert=cert,
                indefinite_length=True
            )

    def tearDown(self):
        self.test_file.close()

    def test_compressed_message(self):
        """ Test Compressed Message received from Mendelson AS2"""

        # Parse the generated AS2 message as the partner
        test_file = os.path.join(TEST_DIR, 'mecas2_compressed.as2')
        with open(test_file, 'rb') as fp:
            in_message = as2.Message()
            in_message.parse(
                fp.read(),
                find_org_cb=self.find_org,
                find_partner_cb=self.find_partner
            )

        # Compare the mic contents of the input and output messages
        self.assertTrue(in_message.compress)
        self.assertEqual(
            self.test_file.read(), in_message.payload.get_payload())

    def test_encrypted_message(self):
        """ Test Encrypted Message received from Mendelson AS2"""

        # Parse the generated AS2 message as the partner
        test_file = os.path.join(TEST_DIR, 'mecas2_encrypted.as2')
        with open(test_file, 'rb') as fp:
            in_message = as2.Message()
            in_message.parse(
                fp.read(),
                find_org_cb=self.find_org,
                find_partner_cb=self.find_partner
            )

        # Compare the mic contents of the input and output messages
        self.assertTrue(in_message.encrypt)
        self.assertEqual(in_message.enc_alg, 'tripledes_192_cbc')
        self.assertEqual(
            self.test_file.read(), in_message.payload.get_payload())

    def test_signed_message(self):
        """ Test Unencrypted Signed Uncompressed Message from Mendelson AS2"""
        # Parse the generated AS2 message as the partner
        test_file = os.path.join(TEST_DIR, 'mecas2_signed.as2')
        with open(test_file, 'rb') as fp:
            in_message = as2.Message()
            in_message.parse(
                fp.read(),
                find_org_cb=self.find_org,
                find_partner_cb=self.find_partner
            )

        # Compare the mic contents of the input and output messages
        self.assertTrue(in_message.sign)
        self.assertEqual(in_message.digest_alg, 'sha1')
        self.assertEqual(
            self.test_file.read(), in_message.payload.get_payload())

    def test_encrypted_signed_message(self):
        """ Test Encrypted Signed Uncompressed Message from Mendelson AS2"""

        # Parse the generated AS2 message as the partner
        test_file = os.path.join(TEST_DIR, 'mecas2_signed_encrypted.as2')
        with open(test_file, 'rb') as fp:
            in_message = as2.Message()
            in_message.parse(
                fp.read(),
                find_org_cb=self.find_org,
                find_partner_cb=self.find_partner
            )

        # Compare the mic contents of the input and output messages
        self.assertTrue(in_message.encrypt)
        self.assertEqual(in_message.enc_alg, 'tripledes_192_cbc')
        self.assertTrue(in_message.sign)
        self.assertEqual(in_message.digest_alg, 'sha1')
        self.assertEqual(
            self.test_file.read(), in_message.payload.get_payload())

    def test_encrypted_signed_compressed_message(self):
        """ Test Encrypted Signed Compressed Message from Mendelson AS2"""

        # Parse the generated AS2 message as the partner
        test_file = os.path.join(
            TEST_DIR, 'mecas2_compressed_signed_encrypted.as2')
        with open(test_file, 'rb') as fp:
            in_message = as2.Message()
            in_message.parse(
                fp.read(),
                find_org_cb=self.find_org,
                find_partner_cb=self.find_partner
            )

        # Compare the mic contents of the input and output messages
        self.assertTrue(in_message.encrypt)
        self.assertEqual(in_message.enc_alg, 'tripledes_192_cbc')
        self.assertTrue(in_message.sign)
        self.assertEqual(in_message.digest_alg, 'sha1')
        self.assertEqual(
            self.test_file.read(), in_message.payload.get_payload())

    def test_unsigned_mdn(self):
        """ Test Unsigned MDN received from Mendelson AS2"""

        # Parse the generated AS2 message as the partner
        test_file = os.path.join(
            TEST_DIR, 'mecas2_unsigned.mdn')
        with open(test_file, 'rb') as fp:
            in_message = as2.MDN()
            with self.assertRaises(exceptions.AS2Exception):
                in_message.parse(fp.read(), find_message_cb=self.find_message)

    def test_signed_mdn(self):
        """ Test Signed MDN received from Mendelson AS2"""

        # Parse the generated AS2 message as the partner
        test_file = os.path.join(
            TEST_DIR, 'mecas2_signed.mdn')
        with open(test_file, 'rb') as fp:
            in_message = as2.MDN()
            in_message.parse(fp.read(), find_message_cb=self.find_message)

    def find_org(self, headers):
        return self.org

    def find_partner(self, headers):
        return self.partner

    def find_message(self, message_id, message_recipient):
        message = as2.Message()
        message.sender = self.org
        message.receiver = self.partner
        message.mic = 'O4bvrm5t2YunRfwvZicNdEUmPaPZ9vUslX8loVLDck0='
        return message
