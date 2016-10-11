from __future__ import unicode_literals, absolute_import, print_function
from .context import pyas2lib
import unittest
import os

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata')


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.test_file = open(os.path.join(TEST_DIR, 'payload.txt'))

    def tearDown(self):
        self.test_file.close()

    def test_unencrypted_unsigned_message(self):
        """ Test Permutation 1: Sender sends un-encrypted data and does
         NOT request a receipt. """

        # Build an As2 message to be transmitted to partner
        out_message = pyas2lib.AS2Message()
        out_mic_content = out_message.build(
            'some_organization', 'some_partner', self.test_file)
        raw_out_message = str(out_message)

        # Parse the generated AS2 message as the partner
        in_message = pyas2lib.AS2Message()
        in_mic_content = in_message.parse(raw_out_message)

        # Compare the mic contents of the input and output messages
        self.assertEqual(in_mic_content, out_mic_content)

    def test_compressed_message(self):
        """Sender sends compressed but unencrypted and unsigned data. """

        # Build an As2 message to be transmitted to partner
        out_message = pyas2lib.AS2Message(compress=True)
        out_mic_content = out_message.build(
            'some_organization', 'some_partner', self.test_file)
        raw_out_message = str(out_message)

        # Parse the generated AS2 message as the partner
        in_message = pyas2lib.AS2Message()
        in_mic_content = in_message.parse(raw_out_message)

        # Compare the mic contents of the input and output messages
        self.assertEqual(in_mic_content, out_mic_content)
