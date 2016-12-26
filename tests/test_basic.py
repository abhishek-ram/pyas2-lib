from __future__ import unicode_literals, absolute_import, print_function
from .context import pyas2lib
import unittest
import os

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata')


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.test_file = open(
                os.path.join(TEST_DIR, 'payload.txt'), 'rb')

    def tearDown(self):
        self.test_file.close()

    def test_plain_message(self):
        """ Test Unencrypted Unsigned Uncompressed Message """

        # Build an As2 message to be transmitted to partner
        out_message = pyas2lib.AS2Message()
        out_message.build(
            'some_organization', 'some_partner', self.test_file)
        raw_out_message = bytes(out_message)

        # Parse the generated AS2 message as the partner
        in_message = pyas2lib.AS2Message()
        in_message.parse(raw_out_message)

        # Compare the mic contents of the input and output messages
        self.test_file.seek(0)
        original_message = self.test_file.read()
        self.assertEqual(original_message,
                         in_message.payload.get_payload(decode=True))

    def test_compressed_message(self):
        """ Test Unencrypted Unsigned Compressed Message """

        # Build an As2 message to be transmitted to partner
        out_message = pyas2lib.AS2Message(compress=True)
        out_mic_content = out_message.build(
            'some_organization', 'some_partner', self.test_file)
        raw_out_message = bytes(out_message)
        # Parse the generated AS2 message as the partner
        in_message = pyas2lib.AS2Message()
        in_mic_content = in_message.parse(raw_out_message)

        # Compare the mic contents of the input and output messages
        self.assertEqual(out_mic_content, in_mic_content.decode('utf-8'))
