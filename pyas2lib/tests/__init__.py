import unittest
import os

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class Pyas2TestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Perform the setup actions for the test case."""
        file_list = {
            "test_data": "payload.txt",
            "test_data_dos": "payload_dos.txt",
            "private_key": "cert_test.p12",
            "public_key": "cert_test_public.pem",
            "mecas2_public_key": "cert_mecas2_public.pem",
            "oldpyas2_public_key": "cert_oldpyas2_public.pem",
            "oldpyas2_private_key": "cert_oldpyas2_private.pem",
            "sb2bi_public_key": "cert_sb2bi_public.pem",
            "sb2bi_public_ca": "cert_sb2bi_public.ca",
            "private_cer": "cert_extract_private.cer",
            "private_pem": "cert_extract_private.pem",
        }

        # Load the files to the attrs
        for attr, filename in file_list.items():
            with open(os.path.join(TEST_DIR, filename), "rb") as fp:
                setattr(cls, attr, fp.read())
