from __future__ import unicode_literals, absolute_import, print_function
from . import Pyas2TestCase, as2, utils
import os
import base64
import datetime


class TestAdvanced(Pyas2TestCase):

    def setUp(self):
        self.org = as2.Organization(
            as2_name='some_organization',
            sign_key=self.private_key,
            sign_key_pass='test',
            decrypt_key=self.private_key,
            decrypt_key_pass='test'
        )
        self.partner = as2.Partner(
            as2_name='some_partner',
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
        test_message_path = os.path.join(self.TEST_DIR, 'payload.binary')
        with open(test_message_path, 'rb') as bin_file:
            original_message = bin_file.read()
            out_message.build(
                original_message,
                filename='payload.binary',
                content_type='application/octet-stream'
            )
        raw_out_message = out_message.headers_str + b'\r\n' + out_message.content

        # Parse the generated AS2 message as the partner
        in_message = as2.Message()
        status, _, _ = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
            find_message_cb=lambda x, y: False
        )

        # Compare the mic contents of the input and output messages
        # self.assertEqual(original_message,
        #                  in_message.payload.get_payload(decode=True))
        self.assertEqual(status, 'processed')
        self.assertTrue(in_message.signed)
        self.assertTrue(in_message.encrypted)
        self.assertEqual(out_message.mic, in_message.mic)

    def test_partner_not_found(self):
        """ Test case where partner and organization is not found """

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.mdn_mode = as2.SYNCHRONOUS_MDN
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        # Parse the generated AS2 message as the partner
        raw_out_message = \
            self.out_message.headers_str + b'\r\n' + self.out_message.content
        in_message = as2.Message()
        _, _, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=lambda x: None,
            find_message_cb=lambda x, y: False
        )

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b'\r\n' + mdn.content,
            find_message_cb=self.find_message
        )

        self.assertEqual(status, 'processed/Error')
        self.assertEqual(detailed_status, 'unknown-trading-partner')

        # Parse again but this time make without organization
        in_message = as2.Message()
        _, _, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=lambda x: None,
            find_partner_cb=self.find_partner,
            find_message_cb=lambda x, y: False
        )

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b'\r\n' + mdn.content,
            find_message_cb=self.find_message
        )
        self.assertEqual(status, 'processed/Error')
        self.assertEqual(detailed_status, 'unknown-trading-partner')

    def test_duplicate_message(self):
        """ Test case where a duplicate message is sent to the partner """

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.encrypt = True
        self.partner.mdn_mode = as2.SYNCHRONOUS_MDN
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        # Parse the generated AS2 message as the partner
        raw_out_message = \
            self.out_message.headers_str + b'\r\n' + self.out_message.content
        in_message = as2.Message()
        _, _, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
            find_message_cb=lambda x, y: True
        )

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b'\r\n' + mdn.content,
            find_message_cb=self.find_message
        )
        self.assertEqual(status, 'processed/Warning')
        self.assertEqual(detailed_status, 'duplicate-document')

    def test_failed_decompression(self):
        """ Test case where message decompression has failed """

        # Build an As2 message to be transmitted to partner
        self.partner.compress = True
        self.partner.mdn_mode = as2.SYNCHRONOUS_MDN
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        # Parse the generated AS2 message as the partner
        raw_out_message = \
            self.out_message.headers_str + b'\r\n' + base64.b64encode(b'xxxxx')
        in_message = as2.Message()
        _, exec_info, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
        )

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b'\r\n' + mdn.content,
            find_message_cb=self.find_message
        )
        self.assertEqual(status, 'processed/Error')
        self.assertEqual(detailed_status, 'decompression-failed')

    def test_insufficient_security(self):
        """ Test case where message security is not as per the configuration """

        # Build an As2 message to be transmitted to partner
        self.partner.mdn_mode = as2.SYNCHRONOUS_MDN
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        # Parse the generated AS2 message as the partner
        self.partner.sign = True
        self.partner.encrypt = True
        raw_out_message = \
            self.out_message.headers_str + b'\r\n' + self.out_message.content
        in_message = as2.Message()
        _, _, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
            find_message_cb=lambda x, y: False
        )

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b'\r\n' + mdn.content,
            find_message_cb=self.find_message
        )
        self.assertEqual(status, 'processed/Error')
        self.assertEqual(detailed_status, 'insufficient-message-security')

    def test_failed_decryption(self):
        """ Test case where message decryption has failed """

        # Build an As2 message to be transmitted to partner
        self.partner.encrypt = True
        self.partner.encrypt_cert = self.mecas2_public_key
        self.partner.validate_certs = False
        self.partner.mdn_mode = as2.SYNCHRONOUS_MDN
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        # Parse the generated AS2 message as the partner
        raw_out_message = \
            self.out_message.headers_str + b'\r\n' + self.out_message.content
        in_message = as2.Message()
        _, exec_info, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
            find_message_cb=lambda x, y: False
        )

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b'\r\n' + mdn.content,
            find_message_cb=self.find_message
        )
        self.assertEqual(status, 'processed/Error')
        self.assertEqual(detailed_status, 'decryption-failed')

    def test_failed_signature(self):
        """ Test case where signature verification has failed """

        # Build an As2 message to be transmitted to partner
        self.partner.sign = True
        self.partner.verify_cert = self.mecas2_public_key
        self.partner.validate_certs = False
        self.partner.mdn_mode = as2.SYNCHRONOUS_MDN
        self.out_message = as2.Message(self.org, self.partner)
        self.out_message.build(self.test_data)

        # Parse the generated AS2 message as the partner
        raw_out_message = \
            self.out_message.headers_str + b'\r\n' + self.out_message.content
        in_message = as2.Message()
        _, exec_info, mdn = in_message.parse(
            raw_out_message,
            find_org_cb=self.find_org,
            find_partner_cb=self.find_partner,
            find_message_cb=lambda x, y: False
        )

        out_mdn = as2.Mdn()
        status, detailed_status = out_mdn.parse(
            mdn.headers_str + b'\r\n' + mdn.content,
            find_message_cb=self.find_message
        )
        self.assertEqual(status, 'processed/Error')
        self.assertEqual(detailed_status, 'authentication-failed')

    def test_verify_certificate(self):
        """ Test case where we have try to load an expired cert  """

        # First test with a certificate with invalid root
        cert_path = os.path.join(self.TEST_DIR, 'verify_cert_test1.pem')
        with open(cert_path, 'rb') as cert_file:
            try:
                as2.Partner(
                    as2_name='some_partner',
                    verify_cert=cert_file.read()
                )
            except as2.AS2Exception as e:
                self.assertIn(
                    'unable to get local issuer certificate', str(e))

        # Test with an expired certificate
        cert_path = os.path.join(self.TEST_DIR, 'verify_cert_test2.cer')
        with open(cert_path, 'rb') as cert_file:
            try:
                as2.Partner(
                    as2_name='some_partner',
                    verify_cert=cert_file.read()
                )
            except as2.AS2Exception as e:
                self.assertIn(
                    'certificate has expired', str(e))

        # Test with a chain certificate
        cert_path = os.path.join(self.TEST_DIR, 'verify_cert_test3.pem')
        with open(cert_path, 'rb') as cert_file:
            try:
                as2.Partner(
                    as2_name='some_partner',
                    verify_cert=cert_file.read()
                )
            except as2.AS2Exception as e:
                self.assertIn(
                    'unable to get local issuer certificate', str(e))

        # Test chain certificate with the ca
        cert_ca_path = os.path.join(self.TEST_DIR, 'verify_cert_test3.ca')
        with open(cert_path, 'rb') as cert_file:
            with open(cert_ca_path, 'rb') as cert_ca_file:
                try:
                    as2.Partner(
                        as2_name='some_partner',
                        verify_cert=cert_file.read(),
                        verify_cert_ca=cert_ca_file.read()
                    )
                except as2.AS2Exception as e:
                    self.fail('Failed to load chain certificate: %s' % e)

    def test_load_private_key(self):
        """ Test case where we have try to load keys in different formats """

        # First test with a pkcs12 key file
        cert_path = os.path.join(self.TEST_DIR, 'cert_test.p12')
        with open(cert_path, 'rb') as cert_file:
            try:
                as2.Organization(
                    as2_name='some_org',
                    sign_key=cert_file.read(),
                    sign_key_pass='test'
                )
            except as2.AS2Exception as e:
                self.fail('Failed to load p12 private key: %s' % e)

        # Now test with a pem encoded key file
        cert_path = os.path.join(self.TEST_DIR, 'cert_test.pem')
        with open(cert_path, 'rb') as cert_file:
            try:
                as2.Organization(
                    as2_name='some_org',
                    sign_key=cert_file.read(),
                    sign_key_pass='test'
                )
            except as2.AS2Exception as e:
                self.fail('Failed to load pem private key: %s' % e)

    def test_extract_certificate_info(self):
        """ Test case that extracts data from private and public certificates
         in PEM or DER format"""

        cert_info = {
            'valid_from': datetime.datetime(2019, 6, 3, 11, 32, 57),
            'valid_to': datetime.datetime(2029, 5, 31, 11, 32, 57),
            'subject': [('C', 'AU'), ('ST', 'Some-State'),
                        ('O', 'pyas2lib'), ('CN', 'test')],
            'issuer': [('C', 'AU'), ('ST', 'Some-State'),
                       ('O', 'pyas2lib'), ('CN', 'test')],
            'serial': 13747137503594840569
        }
        cert_empty = {
            'valid_from': None,
            'valid_to': None,
            'subject': None,
            'issuer': None,
            'serial': None
        }

        # compare result of function with cert_info dict.
        self.assertEqual(
            utils.extract_certificate_info(self.private_pem), cert_info)
        self.assertEqual(
            utils.extract_certificate_info(self.private_cer), cert_info)
        self.assertEqual(
            utils.extract_certificate_info(self.public_pem), cert_info)
        self.assertEqual(
            utils.extract_certificate_info(self.public_cer), cert_info)
        self.assertEqual(utils.extract_certificate_info(b''), cert_empty)

    def find_org(self, headers):
        return self.org

    def find_partner(self, headers):
        return self.partner

    def find_message(self, message_id, message_recipient):
        return self.out_message


class SterlingIntegratorTest(Pyas2TestCase):

    def setUp(self):
        self.org = as2.Organization(
            as2_name='AS2 Server',
            sign_key=self.oldpyas2_private_key,
            sign_key_pass='password',
            decrypt_key=self.oldpyas2_private_key,
            decrypt_key_pass='password'
        )
        self.partner = as2.Partner(
            as2_name='Sterling B2B Integrator',
            verify_cert=self.sb2bi_public_key,
            verify_cert_ca=self.sb2bi_public_ca,
            encrypt_cert=self.sb2bi_public_key,
            encrypt_cert_ca=self.sb2bi_public_ca,
        )

    def xtest_process_message(self):
        """ Test processing message received from Sterling Integrator"""
        with open(os.path.join(
                self.TEST_DIR, 'sb2bi_signed_cmp.msg'), 'rb') as msg:
            as2message = as2.Message()
            status, exception, as2mdn = as2message.parse(
                msg.read(),
                lambda x: self.org,
                lambda y: self.partner,
                lambda x, y: False
            )
            self.assertEqual(status, 'processed')

    def test_process_mdn(self):
        """ Test processing mdn received from Sterling Integrator"""
        message = as2.Message(sender=self.org, receiver=self.partner)
        message.message_id = '151694007918.24690.7052273208458909245@' \
                             'ip-172-31-14-209.ec2.internal'

        as2mdn = as2.Mdn()
        # Parse the mdn and get the message status
        with open(os.path.join(
                self.TEST_DIR, 'sb2bi_signed.mdn'), 'rb') as mdn:
            status, detailed_status = as2mdn.parse(
                mdn.read(), lambda x, y: message)
        self.assertEqual(status, 'processed')
