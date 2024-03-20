"""Module to test cms related features of pyas2lib."""
import os

import pytest
from oscrypto import asymmetric, symmetric, util

from asn1crypto import algos, cms as crypto_cms, core

from pyas2lib.as2 import Organization
from pyas2lib import cms
from pyas2lib.exceptions import (
    AS2Exception,
    DecompressionError,
    DecryptionError,
    IntegrityError,
)
from pyas2lib.tests import TEST_DIR


INVALID_DATA = cms.cms.ContentInfo(
    {
        "content_type": cms.cms.ContentType("data"),
    }
).dump()


def encrypted_data_with_faulty_key_algo():
    with open(os.path.join(TEST_DIR, "cert_test_public.pem"), "rb") as fp:
        encrypt_cert = asymmetric.load_certificate(fp.read())
    enc_alg_list = "rc4_128_cbc".split("_")
    cipher, key_length, _ = enc_alg_list[0], enc_alg_list[1], enc_alg_list[2]
    key = util.rand_bytes(int(key_length) // 8)
    algorithm_id = "1.2.840.113549.3.4"
    encrypted_content = symmetric.rc4_encrypt(key, b"data")
    enc_alg_asn1 = algos.EncryptionAlgorithm(
        {
            "algorithm": algorithm_id,
        }
    )
    encrypted_key = asymmetric.rsa_oaep_encrypt(encrypt_cert, key)
    return crypto_cms.ContentInfo(
        {
            "content_type": crypto_cms.ContentType("enveloped_data"),
            "content": crypto_cms.EnvelopedData(
                {
                    "version": crypto_cms.CMSVersion("v0"),
                    "recipient_infos": [
                        crypto_cms.KeyTransRecipientInfo(
                            {
                                "version": crypto_cms.CMSVersion("v0"),
                                "rid": crypto_cms.RecipientIdentifier(
                                    {
                                        "issuer_and_serial_number": crypto_cms.IssuerAndSerialNumber(
                                            {
                                                "issuer": encrypt_cert.asn1[
                                                    "tbs_certificate"
                                                ]["issuer"],
                                                "serial_number": encrypt_cert.asn1[
                                                    "tbs_certificate"
                                                ]["serial_number"],
                                            }
                                        )
                                    }
                                ),
                                "key_encryption_algorithm": crypto_cms.KeyEncryptionAlgorithm(
                                    {
                                        "algorithm": crypto_cms.KeyEncryptionAlgorithmId(
                                            "aes128_wrap"
                                        )
                                    }
                                ),
                                "encrypted_key": crypto_cms.OctetString(encrypted_key),
                            }
                        )
                    ],
                    "encrypted_content_info": crypto_cms.EncryptedContentInfo(
                        {
                            "content_type": crypto_cms.ContentType("data"),
                            "content_encryption_algorithm": enc_alg_asn1,
                            "encrypted_content": encrypted_content,
                        }
                    ),
                }
            ),
        }
    ).dump()


def test_compress():
    """Test the compression and decompression functions."""
    compressed_data = cms.compress_message(b"data")
    assert cms.decompress_message(compressed_data) == b"data"

    with pytest.raises(DecompressionError):
        cms.decompress_message(INVALID_DATA)


def test_signing():
    """Test the signing and verification functions."""
    # Load the signature key
    with open(os.path.join(TEST_DIR, "cert_test.p12"), "rb") as fp:
        sign_key = Organization.load_key(fp.read(), "test")
    with open(os.path.join(TEST_DIR, "cert_test_public.pem"), "rb") as fp:
        verify_cert = asymmetric.load_certificate(fp.read())

    # Test failure of signature verification
    with pytest.raises(IntegrityError):
        cms.verify_message(b"data", INVALID_DATA, None)

    # Test signature without signed attributes
    cms.sign_message(
        b"data", digest_alg="sha256", sign_key=sign_key, use_signed_attributes=False
    )

    # Test pss signature and verification
    signature = cms.sign_message(
        b"data", digest_alg="sha256", sign_key=sign_key, sign_alg="rsassa_pss"
    )
    cms.verify_message(b"data", signature, verify_cert)

    # Test unsupported signature alg
    with pytest.raises(AS2Exception):
        cms.sign_message(
            b"data", digest_alg="sha256", sign_key=sign_key, sign_alg="rsassa_pssa"
        )

    # Test unsupported digest alg
    with pytest.raises(AS2Exception):
        cms.sign_message(
            b"data",
            digest_alg="sha-256",
            sign_key=sign_key,
            use_signed_attributes=False,
        )


def test_encryption():
    """Test the encryption and decryption functions."""
    with open(os.path.join(TEST_DIR, "cert_test.p12"), "rb") as fp:
        decrypt_key = Organization.load_key(fp.read(), "test")
    with open(os.path.join(TEST_DIR, "cert_test_public.pem"), "rb") as fp:
        encrypt_cert = asymmetric.load_certificate(fp.read())

    with pytest.raises(DecryptionError):
        cms.decrypt_message(INVALID_DATA, None)

    # Test all the encryption algorithms
    enc_algorithms = [
        "rc2_128_cbc",
        "rc4_128_cbc",
        "aes_128_cbc",
        "aes_192_cbc",
        "aes_256_cbc",
        "tripledes_192_cbc",
    ]

    key_enc_algos = [
        "rsaes_oaep",
        "rsaes_pkcs1v15",
    ]

    encryption_algos = [
        (alg, key_algo) for alg in enc_algorithms for key_algo in key_enc_algos
    ]

    for enc_algorithm, encryption_scheme in encryption_algos:
        encrypted_data = cms.encrypt_message(
            b"data", enc_algorithm, encrypt_cert, encryption_scheme
        )
        _, decrypted_data = cms.decrypt_message(encrypted_data, decrypt_key)
        assert decrypted_data == b"data"

    # Test no encryption algorithm
    with pytest.raises(AS2Exception):
        cms.encrypt_message(b"data", "rc5_128_cbc", encrypt_cert)

    # Test no encryption algorithm on decrypt
    encrypted_data = cms.encrypt_message(b"data", "des_64_cbc", encrypt_cert)
    with pytest.raises(AS2Exception):
        cms.decrypt_message(encrypted_data, decrypt_key)

    # Test faulty key encryption algorithm
    with pytest.raises(AS2Exception):
        cms.encrypt_message(b"data", "rc2_128_cbc", encrypt_cert, "des_64_cbc")

    # Test unsupported key encryption algorithm
    encrypted_data = encrypted_data_with_faulty_key_algo()
    with pytest.raises(AS2Exception):
        cms.decrypt_message(encrypted_data, decrypt_key)
