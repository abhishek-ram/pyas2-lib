"""Define functions related to the CMS operations such as encrypting, signature, etc."""
import hashlib
import zlib
from collections import OrderedDict
from datetime import datetime, timezone

from asn1crypto import cms, core, algos
from oscrypto import asymmetric, symmetric, util

from pyas2lib.exceptions import (
    AS2Exception,
    DecompressionError,
    DecryptionError,
    IntegrityError,
)
from pyas2lib.constants import DIGEST_ALGORITHMS
from pyas2lib.utils import normalize_digest_alg


def compress_message(data_to_compress):
    """Function compresses data and returns the generated ASN.1

    :param data_to_compress: A byte string of the data to be compressed

    :return: A CMS ASN.1 byte string of the compressed data.
    """
    compressed_content = cms.ParsableOctetString(zlib.compress(data_to_compress))
    return cms.ContentInfo(
        {
            "content_type": cms.ContentType("compressed_data"),
            "content": cms.CompressedData(
                {
                    "version": cms.CMSVersion("v0"),
                    "compression_algorithm": cms.CompressionAlgorithm(
                        {"algorithm": cms.CompressionAlgorithmId("zlib")}
                    ),
                    "encap_content_info": cms.EncapsulatedContentInfo(
                        {
                            "content_type": cms.ContentType("data"),
                            "content": compressed_content,
                        }
                    ),
                }
            ),
        }
    ).dump()


def decompress_message(compressed_data):
    """Function parses an ASN.1 compressed message and extracts/decompresses
    the original message.

    :param compressed_data: A CMS ASN.1 byte string containing the compressed
    data.

    :return: A byte string containing the decompressed original message.
    """
    try:
        cms_content = cms.ContentInfo.load(compressed_data)
        if cms_content["content_type"].native == "compressed_data":
            return cms_content["content"].decompressed
        raise DecompressionError("Compressed data not found in ASN.1 ")

    except Exception as e:
        raise DecompressionError("Decompression failed with cause: {}".format(e)) from e


def encrypt_message(data_to_encrypt, enc_alg, encryption_cert):
    """Function encrypts data and returns the generated ASN.1

    :param data_to_encrypt: A byte string of the data to be encrypted
    :param enc_alg: The algorithm to be used for encrypting the data
    :param encryption_cert: The certificate to be used for encrypting the data

    :return: A CMS ASN.1 byte string of the encrypted data.
    """

    enc_alg_list = enc_alg.split("_")
    cipher, key_length, _ = enc_alg_list[0], enc_alg_list[1], enc_alg_list[2]

    # Generate the symmetric encryption key and encrypt the message
    key = util.rand_bytes(int(key_length) // 8)
    if cipher == "tripledes":
        algorithm_id = "1.2.840.113549.3.7"
        iv, encrypted_content = symmetric.tripledes_cbc_pkcs5_encrypt(
            key, data_to_encrypt, None
        )
        enc_alg_asn1 = algos.EncryptionAlgorithm(
            {"algorithm": algorithm_id, "parameters": cms.OctetString(iv)}
        )

    elif cipher == "rc2":
        algorithm_id = "1.2.840.113549.3.2"
        iv, encrypted_content = symmetric.rc2_cbc_pkcs5_encrypt(
            key, data_to_encrypt, None
        )
        enc_alg_asn1 = algos.EncryptionAlgorithm(
            {
                "algorithm": algorithm_id,
                "parameters": algos.Rc2Params({"iv": cms.OctetString(iv)}),
            }
        )

    elif cipher == "rc4":
        algorithm_id = "1.2.840.113549.3.4"
        encrypted_content = symmetric.rc4_encrypt(key, data_to_encrypt)
        enc_alg_asn1 = algos.EncryptionAlgorithm(
            {
                "algorithm": algorithm_id,
            }
        )

    elif cipher == "aes":
        if key_length == "128":
            algorithm_id = "2.16.840.1.101.3.4.1.2"
        elif key_length == "192":
            algorithm_id = "2.16.840.1.101.3.4.1.22"
        else:
            algorithm_id = "2.16.840.1.101.3.4.1.42"

        iv, encrypted_content = symmetric.aes_cbc_pkcs7_encrypt(
            key, data_to_encrypt, None
        )
        enc_alg_asn1 = algos.EncryptionAlgorithm(
            {"algorithm": algorithm_id, "parameters": cms.OctetString(iv)}
        )
    elif cipher == "des":
        algorithm_id = "1.3.14.3.2.7"
        iv, encrypted_content = symmetric.des_cbc_pkcs5_encrypt(
            key, data_to_encrypt, None
        )
        enc_alg_asn1 = algos.EncryptionAlgorithm(
            {"algorithm": algorithm_id, "parameters": cms.OctetString(iv)}
        )
    else:
        raise AS2Exception("Unsupported Encryption Algorithm")

    # Encrypt the key and build the ASN.1 message
    encrypted_key = asymmetric.rsa_pkcs1v15_encrypt(encryption_cert, key)

    return cms.ContentInfo(
        {
            "content_type": cms.ContentType("enveloped_data"),
            "content": cms.EnvelopedData(
                {
                    "version": cms.CMSVersion("v0"),
                    "recipient_infos": [
                        cms.KeyTransRecipientInfo(
                            {
                                "version": cms.CMSVersion("v0"),
                                "rid": cms.RecipientIdentifier(
                                    {
                                        "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                                            {
                                                "issuer": encryption_cert.asn1[
                                                    "tbs_certificate"
                                                ]["issuer"],
                                                "serial_number": encryption_cert.asn1[
                                                    "tbs_certificate"
                                                ]["serial_number"],
                                            }
                                        )
                                    }
                                ),
                                "key_encryption_algorithm": cms.KeyEncryptionAlgorithm(
                                    {"algorithm": cms.KeyEncryptionAlgorithmId("rsa")}
                                ),
                                "encrypted_key": cms.OctetString(encrypted_key),
                            }
                        )
                    ],
                    "encrypted_content_info": cms.EncryptedContentInfo(
                        {
                            "content_type": cms.ContentType("data"),
                            "content_encryption_algorithm": enc_alg_asn1,
                            "encrypted_content": encrypted_content,
                        }
                    ),
                }
            ),
        }
    ).dump()


def decrypt_message(encrypted_data, decryption_key):
    """Function parses an ASN.1 encrypted message and extracts/decrypts the original message.

    :param encrypted_data: A CMS ASN.1 byte string containing the encrypted data.
    :param decryption_key: The key to be used for decrypting the data.

    :return: A byte string containing the decrypted original message.
    """

    cms_content = cms.ContentInfo.load(encrypted_data)
    cipher, decrypted_content = None, None

    if cms_content["content_type"].native == "enveloped_data":
        recipient_info = cms_content["content"]["recipient_infos"][0].parse()
        key_enc_alg = recipient_info["key_encryption_algorithm"]["algorithm"].native
        encrypted_key = recipient_info["encrypted_key"].native

        if cms.KeyEncryptionAlgorithmId(key_enc_alg) == cms.KeyEncryptionAlgorithmId(
            "rsa"
        ):
            try:
                key = asymmetric.rsa_pkcs1v15_decrypt(decryption_key[0], encrypted_key)
            except Exception as e:
                raise DecryptionError(
                    "Failed to decrypt the payload: Could not extract decryption key."
                ) from e

            alg = cms_content["content"]["encrypted_content_info"][
                "content_encryption_algorithm"
            ]
            encapsulated_data = cms_content["content"]["encrypted_content_info"][
                "encrypted_content"
            ].native

            try:
                if alg["algorithm"].native == "rc4":
                    decrypted_content = symmetric.rc4_decrypt(key, encapsulated_data)
                elif alg.encryption_cipher == "tripledes":
                    cipher = "tripledes_192_cbc"
                    decrypted_content = symmetric.tripledes_cbc_pkcs5_decrypt(
                        key, encapsulated_data, alg.encryption_iv
                    )
                elif alg.encryption_cipher == "aes":
                    decrypted_content = symmetric.aes_cbc_pkcs7_decrypt(
                        key, encapsulated_data, alg.encryption_iv
                    )
                elif alg.encryption_cipher == "rc2":
                    decrypted_content = symmetric.rc2_cbc_pkcs5_decrypt(
                        key, encapsulated_data, alg["parameters"]["iv"].native
                    )
                else:
                    raise AS2Exception("Unsupported Encryption Algorithm")
            except Exception as e:
                raise DecryptionError(
                    "Failed to decrypt the payload: {}".format(e)
                ) from e
        else:
            raise AS2Exception("Unsupported Encryption Algorithm")
    else:
        raise DecryptionError("Encrypted data not found in ASN.1 ")

    return cipher, decrypted_content


def sign_message(
    data_to_sign,
    digest_alg,
    sign_key,
    sign_alg="rsassa_pkcs1v15",
    use_signed_attributes=True,
):
    """Function signs the data and returns the generated ASN.1

    :param data_to_sign: A byte string of the data to be signed.

    :param digest_alg: The digest algorithm to be used for generating the signature.

    :param sign_key: The key to be used for generating the signature.

    :param sign_alg: The algorithm to be used for signing the message.

    :param use_signed_attributes: Optional attribute to indicate weather the
    CMS signature attributes should be included in the signature or not.

    :return: A CMS ASN.1 byte string of the signed data.
    """
    digest_alg = normalize_digest_alg(digest_alg)
    if digest_alg not in DIGEST_ALGORITHMS:
        raise AS2Exception("Unsupported Digest Algorithm")

    if use_signed_attributes:
        digest_func = hashlib.new(digest_alg)
        digest_func.update(data_to_sign)
        message_digest = digest_func.digest()

        class SmimeCapability(core.Sequence):
            """Define the possible list of Smime Capability."""

            _fields = [
                ("0", core.Any, {"optional": True}),
                ("1", core.Any, {"optional": True}),
                ("2", core.Any, {"optional": True}),
                ("3", core.Any, {"optional": True}),
                ("4", core.Any, {"optional": True}),
            ]

        class SmimeCapabilities(core.Sequence):
            """Define the Smime Capabilities supported by pyas2."""

            _fields = [
                ("0", SmimeCapability),
                ("1", SmimeCapability, {"optional": True}),
                ("2", SmimeCapability, {"optional": True}),
                ("3", SmimeCapability, {"optional": True}),
                ("4", SmimeCapability, {"optional": True}),
                ("5", SmimeCapability, {"optional": True}),
            ]

        smime_cap = OrderedDict(
            [
                (
                    "0",
                    OrderedDict(
                        [("0", core.ObjectIdentifier("2.16.840.1.101.3.4.1.42"))]
                    ),
                ),
                (
                    "1",
                    OrderedDict(
                        [("0", core.ObjectIdentifier("2.16.840.1.101.3.4.1.2"))]
                    ),
                ),
                (
                    "2",
                    OrderedDict([("0", core.ObjectIdentifier("1.2.840.113549.3.7"))]),
                ),
                (
                    "3",
                    OrderedDict(
                        [
                            ("0", core.ObjectIdentifier("1.2.840.113549.3.2")),
                            ("1", core.Integer(128)),
                        ]
                    ),
                ),
                (
                    "4",
                    OrderedDict(
                        [
                            ("0", core.ObjectIdentifier("1.2.840.113549.3.4")),
                            ("1", core.Integer(128)),
                        ]
                    ),
                ),
            ]
        )

        signed_attributes = cms.CMSAttributes(
            [
                cms.CMSAttribute(
                    {
                        "type": cms.CMSAttributeType("content_type"),
                        "values": cms.SetOfContentType([cms.ContentType("data")]),
                    }
                ),
                cms.CMSAttribute(
                    {
                        "type": cms.CMSAttributeType("signing_time"),
                        "values": cms.SetOfTime(
                            [
                                cms.Time(
                                    {
                                        "utc_time": core.UTCTime(
                                            datetime.utcnow().replace(
                                                tzinfo=timezone.utc
                                            )
                                        )
                                    }
                                )
                            ]
                        ),
                    }
                ),
                cms.CMSAttribute(
                    {
                        "type": cms.CMSAttributeType("message_digest"),
                        "values": cms.SetOfOctetString(
                            [core.OctetString(message_digest)]
                        ),
                    }
                ),
                cms.CMSAttribute(
                    {
                        "type": cms.CMSAttributeType("1.2.840.113549.1.9.15"),
                        "values": cms.SetOfAny(
                            [core.Any(SmimeCapabilities(smime_cap))]
                        ),
                    }
                ),
            ]
        )
    else:
        signed_attributes = None

    # Generate the signature
    data_to_sign = signed_attributes.dump() if signed_attributes else data_to_sign
    if sign_alg == "rsassa_pkcs1v15":
        signature = asymmetric.rsa_pkcs1v15_sign(sign_key[0], data_to_sign, digest_alg)
    elif sign_alg == "rsassa_pss":
        signature = asymmetric.rsa_pss_sign(sign_key[0], data_to_sign, digest_alg)
    else:
        raise AS2Exception("Unsupported Signature Algorithm")

    return cms.ContentInfo(
        {
            "content_type": cms.ContentType("signed_data"),
            "content": cms.SignedData(
                {
                    "version": cms.CMSVersion("v1"),
                    "digest_algorithms": cms.DigestAlgorithms(
                        [
                            algos.DigestAlgorithm(
                                {"algorithm": algos.DigestAlgorithmId(digest_alg)}
                            )
                        ]
                    ),
                    "encap_content_info": cms.ContentInfo(
                        {"content_type": cms.ContentType("data")}
                    ),
                    "certificates": cms.CertificateSet(
                        [cms.CertificateChoices({"certificate": sign_key[1].asn1})]
                    ),
                    "signer_infos": cms.SignerInfos(
                        [
                            cms.SignerInfo(
                                {
                                    "version": cms.CMSVersion("v1"),
                                    "sid": cms.SignerIdentifier(
                                        {
                                            "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                                                {
                                                    "issuer": sign_key[1].asn1[
                                                        "tbs_certificate"
                                                    ]["issuer"],
                                                    "serial_number": sign_key[1].asn1[
                                                        "tbs_certificate"
                                                    ]["serial_number"],
                                                }
                                            )
                                        }
                                    ),
                                    "digest_algorithm": algos.DigestAlgorithm(
                                        {
                                            "algorithm": algos.DigestAlgorithmId(
                                                digest_alg
                                            )
                                        }
                                    ),
                                    "signed_attrs": signed_attributes,
                                    "signature_algorithm": algos.SignedDigestAlgorithm(
                                        {
                                            "algorithm": algos.SignedDigestAlgorithmId(
                                                sign_alg
                                            )
                                        }
                                    ),
                                    "signature": core.OctetString(signature),
                                }
                            )
                        ]
                    ),
                }
            ),
        }
    ).dump()


def verify_message(data_to_verify, signature, verify_cert):
    """Function parses an ASN.1 encrypted message and extracts/decrypts the original message.

    :param data_to_verify: A byte string of the data to be verified against the signature.
    :param signature: A CMS ASN.1 byte string containing the signature.
    :param verify_cert: The certificate to be used for verifying the signature.

    :return: The digest algorithm that was used in the signature.
    """

    cms_content = cms.ContentInfo.load(signature)
    digest_alg = None
    if cms_content["content_type"].native == "signed_data":

        for signer in cms_content["content"]["signer_infos"]:

            digest_alg = normalize_digest_alg(
                signer["digest_algorithm"]["algorithm"].native
            )
            if digest_alg not in DIGEST_ALGORITHMS:
                raise Exception("Unsupported Digest Algorithm")

            sig_alg = signer["signature_algorithm"].signature_algo
            sig = signer["signature"].native
            signed_data = data_to_verify

            if signer["signed_attrs"]:
                attr_dict = {}
                for attr in signer["signed_attrs"]:
                    try:
                        attr_dict[attr.native["type"]] = attr.native["values"]
                    except (ValueError, KeyError):
                        continue

                message_digest = bytes()
                for d in attr_dict["message_digest"]:
                    message_digest += d

                digest_func = hashlib.new(digest_alg)
                digest_func.update(data_to_verify)
                calc_message_digest = digest_func.digest()
                if message_digest != calc_message_digest:
                    raise IntegrityError(
                        "Failed to verify message signature: Message Digest does not match."
                    )

                signed_data = signer["signed_attrs"].untag().dump()

            try:
                if sig_alg == "rsassa_pkcs1v15":
                    asymmetric.rsa_pkcs1v15_verify(
                        verify_cert, sig, signed_data, digest_alg
                    )
                elif sig_alg == "rsassa_pss":
                    asymmetric.rsa_pss_verify(verify_cert, sig, signed_data, digest_alg)
                else:
                    raise AS2Exception("Unsupported Signature Algorithm")
            except Exception as e:
                raise IntegrityError(
                    "Failed to verify message signature: {}".format(e)
                ) from e
    else:
        raise IntegrityError("Signed data not found in ASN.1 ")

    return digest_alg
