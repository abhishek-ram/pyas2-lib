import unittest
import os
import sys
sys.path.insert(0, os.path.abspath('..'))

from pyas2lib import as2, exceptions


class PYAS2TestCase(unittest.TestCase):
    TEST_DIR = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'fixtures')

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(cls.TEST_DIR, 'payload.txt'), 'rb') as t_file:
            cls.test_data = t_file.read()

        with open(os.path.join(
                cls.TEST_DIR, 'cert_test.p12'), 'rb') as key_file:
            cls.private_key = key_file.read()

        with open(os.path.join(
                cls.TEST_DIR, 'cert_test_public.pem'), 'rb') as pub_file:
            cls.public_key = pub_file.read()

        with open(os.path.join(
                cls.TEST_DIR, 'cert_mecas2_public.pem'), 'rb') as pub_file:
            cls.mecas2_public_key = pub_file.read()

        with open(os.path.join(
                cls.TEST_DIR, 'cert_oldpyas2_public.pem'), 'rb') as pub_file:
            cls.oldpyas2_public_key = pub_file.read()
