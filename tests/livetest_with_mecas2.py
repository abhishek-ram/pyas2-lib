from __future__ import unicode_literals, absolute_import, print_function
from . import as2, Pyas2TestCase
import requests
import os

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata')


class LiveTestMecAS2(Pyas2TestCase):

    def setUp(self):
        self.org = as2.Organization(
            as2_name='pyas2lib',
            sign_key=self.private_key,
            sign_key_pass='test'.encode('utf-8'),
            decrypt_key=self.private_key,
            decrypt_key_pass='test'.encode('utf-8')
        )

        self.partner = as2.Partner(
            as2_name='mecas2',
            verify_cert=self.mecas2_public_key,
            encrypt_cert=self.mecas2_public_key,
            mdn_mode=as2.SYNCHRONOUS_MDN,
            mdn_digest_alg='sha256'
        )
        self.out_message = None

    def test_compressed_message(self):
        """ Send Unencrypted Unsigned Compressed  Message to Mendelson AS2"""

        self.partner.compress = True
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        response = requests.post(
            'http://localhost:8080/as2/HttpReceiver',
            headers=self.out_message.headers,
            data=self.out_message.content
        )
        raw_mdn = ''
        for k, v in response.headers.items():
            raw_mdn += '{}: {}\n'.format(k, v)

        raw_mdn = raw_mdn + '\n' + response.text

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            raw_mdn, find_message_cb=self.find_message)
        self.assertEqual(status, 'processed')

    def test_encrypted_message(self):
        """ Send Encrypted Unsigned Uncompressed Message to Mendelson AS2"""

        self.partner.encrypt = True
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        response = requests.post(
            'http://localhost:8080/as2/HttpReceiver',
            headers=self.out_message.headers,
            data=self.out_message.content
        )
        raw_mdn = ''
        for k, v in response.headers.items():
            raw_mdn += '{}: {}\n'.format(k, v)

        raw_mdn = raw_mdn + '\n' + response.text

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            raw_mdn, find_message_cb=self.find_message)
        self.assertEqual(status, 'processed')

    def test_signed_message(self):
        """ Send Unencrypted Signed Uncompressed Message to Mendelson AS2"""

        self.partner.sign = True
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        response = requests.post(
            'http://localhost:8080/as2/HttpReceiver',
            data=self.out_message.content,
            headers=self.out_message.headers,
        )

        raw_mdn = ''
        for k, v in response.headers.items():
            raw_mdn += '{}: {}\n'.format(k, v)
        raw_mdn = raw_mdn + '\n' + response.text

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            raw_mdn, find_message_cb=self.find_message)
        self.assertEqual(status, 'processed')

    def test_encrypted_signed_message(self):
        """ Send Encrypted Signed Uncompressed Message to Mendelson AS2"""

        self.partner.sign = True
        self.partner.encrypt = True
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        response = requests.post(
            'http://localhost:8080/as2/HttpReceiver',
            data=self.out_message.content,
            headers=self.out_message.headers,
        )

        raw_mdn = ''
        for k, v in response.headers.items():
            raw_mdn += '{}: {}\n'.format(k, v)
        raw_mdn = raw_mdn + '\n' + response.text

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            raw_mdn, find_message_cb=self.find_message)
        self.assertEqual(status, 'processed')

    def test_encrypted_signed_compressed_message(self):
        """ Send Encrypted Signed Compressed Message to Mendelson AS2"""

        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.compress = True
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        response = requests.post(
            'http://localhost:8080/as2/HttpReceiver',
            data=self.out_message.content,
            headers=self.out_message.headers,
        )

        raw_mdn = ''
        for k, v in response.headers.items():
            raw_mdn += '{}: {}\n'.format(k, v)
        raw_mdn = raw_mdn + '\n' + response.text

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            raw_mdn, find_message_cb=self.find_message)
        self.assertEqual(status, 'processed')

    def find_org(self, headers):
        return self.org

    def find_partner(self, headers):
        return self.partner

    def find_message(self, message_id, message_recipient):
        return self.out_message
