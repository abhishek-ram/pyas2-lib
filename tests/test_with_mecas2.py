from __future__ import unicode_literals, absolute_import, print_function
from .context import pyas2lib
import unittest
import os

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata')


class TestMecAS2(unittest.TestCase):

    def setUp(self):
        self.test_file = open(
                os.path.join(TEST_DIR, 'payload.txt'))

    def tearDown(self):
        self.test_file.close()

    def test_compressed_message(self):
        """ Test Compressed Message received from Mendelson AS2"""

        # Parse the generated AS2 message as the partner
        with open(os.path.join(TEST_DIR, 'mecas2_compressed.as2'), 'rb') as infile:
            in_message = pyas2lib.AS2Message()
            in_message.parse(infile.read())

        # Compare the mic contents of the input and output messages
        self.assertEqual(
            self.test_file.read(), in_message.payload.get_payload())

    def ztest_encrypted_message(self):
        """ Test Encrypted Message received from Mendelson AS2"""

        # Parse the generated AS2 message as the partner
        with open(os.path.join(TEST_DIR, 'mecas2_encrypted.as2')) as infile:
            in_message = pyas2lib.AS2Message()
            in_mic_content = in_message.parse(infile.read())

        # Compare the mic contents of the input and output messages
        # self.assertEqual(out_mic_content, in_mic_content.decode('utf-8'))
