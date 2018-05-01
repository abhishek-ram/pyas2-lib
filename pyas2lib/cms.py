from __future__ import absolute_import, unicode_literals
from asn1crypto import cms, core, algos
from oscrypto import asymmetric, symmetric, util
from datetime import datetime
from collections import OrderedDict
from .compat import byte_cls
from .exceptions import *
import hashlib
import zlib

DIGEST_ALGORITHMS = (
    'md5',
    'sha1',
    'sha224',
    'sha256',
    'sha384',
    'sha512'
)
ENCRYPTION_ALGORITHMS = (
    'tripledes_192_cbc',
    'rc2_128_cbc',
    'rc4_128_cbc'
)


def compress_message(data_to_compress):
    """Function compresses data and returns the generated ASN.1
    
    :param data_to_compress: A byte string of the data to be compressed
    
    :return: A CMS ASN.1 byte string of the compressed data.    
    """
    compressed_content = cms.ParsableOctetString(
        zlib.compress(data_to_compress))
    return cms.ContentInfo({
        'content_type': cms.ContentType('compressed_data'),
        'content': cms.CompressedData({
            'version': cms.CMSVersion('v0'),
            'compression_algorithm':
                cms.CompressionAlgorithm({
                    'algorithm': cms.CompressionAlgorithmId('zlib')
                }),
            'encap_content_info': cms.EncapsulatedContentInfo({
                'content_type': cms.ContentType('data'),
                'content': compressed_content
            })
        })
    }).dump()


def decompress_message(compressed_data):
    """Function parses an ASN.1 compressed message and extracts/decompresses 
    the original message.
     
    :param compressed_data: A CMS ASN.1 byte string containing the compressed 
    data.

    :return: A byte string containing the decompressed original message.    
    """
    try:
        cms_content = cms.ContentInfo.load(compressed_data)

        if cms_content['content_type'].native == 'compressed_data':
            return cms_content['content'].decompressed
        else:
            raise DecompressionError('Compressed data not found in ASN.1 ')

    except Exception as e:
        raise DecompressionError(
            'Decompression failed with cause: {}'.format(e))


def encrypt_message(data_to_encrypt, enc_alg, encryption_cert):
    """Function encrypts data and returns the generated ASN.1

    :param data_to_encrypt: A byte string of the data to be encrypted
    
    :param enc_alg: The algorithm to be used for encrypting the data
    
    :param encryption_cert: The certificate to be used for encrypting the data

    :return: A CMS ASN.1 byte string of the encrypted data.    
    """

    enc_alg_list = enc_alg.split('_')
    cipher, key_length, mode = enc_alg_list[0], enc_alg_list[1], enc_alg_list[2]
    enc_alg_asn1, key, encrypted_content = None, None, None

    # Generate the symmetric encryption key and encrypt the message
    if cipher == 'tripledes':
        key = util.rand_bytes(int(key_length)//8)
        iv, encrypted_content = symmetric.tripledes_cbc_pkcs5_encrypt(
            key, data_to_encrypt, None)
        enc_alg_asn1 = algos.EncryptionAlgorithm({
            'algorithm': algos.EncryptionAlgorithmId('tripledes_3key'),
            'parameters': cms.OctetString(iv)
        })

    # Encrypt the key and build the ASN.1 message
    encrypted_key = asymmetric.rsa_pkcs1v15_encrypt(encryption_cert, key)

    return cms.ContentInfo({
        'content_type': cms.ContentType('enveloped_data'),
        'content': cms.EnvelopedData({
            'version': cms.CMSVersion('v0'),
            'recipient_infos': [
                cms.KeyTransRecipientInfo({
                    'version': cms.CMSVersion('v0'),
                    'rid': cms.RecipientIdentifier({
                        'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                            'issuer': encryption_cert.asn1[
                                'tbs_certificate']['issuer'],
                            'serial_number': encryption_cert.asn1[
                                'tbs_certificate']['serial_number']
                        })
                    }),
                    'key_encryption_algorithm': cms.KeyEncryptionAlgorithm({
                        'algorithm': cms.KeyEncryptionAlgorithmId('rsa')
                    }),
                    'encrypted_key': cms.OctetString(encrypted_key)
                })
            ],
            'encrypted_content_info': cms.EncryptedContentInfo({
                'content_type': cms.ContentType('data'),
                'content_encryption_algorithm': enc_alg_asn1,
                'encrypted_content': encrypted_content
            })
        })
    }).dump()


def decrypt_message(encrypted_data, decryption_key):
    """Function parses an ASN.1 encrypted message and extracts/decrypts 
        the original message.

    :param encrypted_data: A CMS ASN.1 byte string containing the encrypted 
    data.
    
    :param decryption_key: The key to be used for decrypting the data.

    :return: A byte string containing the decrypted original message.    
    """

    cms_content = cms.ContentInfo.load(encrypted_data)
    cipher, decrypted_content = None, None

    if cms_content['content_type'].native == 'enveloped_data':
        recipient_info = cms_content['content']['recipient_infos'][0].parse()
        key_enc_alg = recipient_info[
            'key_encryption_algorithm']['algorithm'].native
        encrypted_key = recipient_info['encrypted_key'].native

        if key_enc_alg == 'rsa':
            try:
                key = asymmetric.rsa_pkcs1v15_decrypt(
                    decryption_key[0], encrypted_key)
            except Exception as e:
                raise DecryptionError('Failed to decrypt the payload: '
                                      'Could not extract decryption key.')
            alg = cms_content['content']['encrypted_content_info'][
                'content_encryption_algorithm']

            encapsulated_data = cms_content['content'][
                'encrypted_content_info']['encrypted_content'].native

            try:
                if alg.encryption_cipher == 'tripledes':
                    cipher = 'tripledes_192_cbc'
                    decrypted_content = symmetric.tripledes_cbc_pkcs5_decrypt(
                        key, encapsulated_data, alg.encryption_iv)
                else:
                    raise AS2Exception('Unsupported Encryption Algorithm')
            except Exception as e:
                raise DecryptionError(
                    'Failed to decrypt the payload: {}'.format(e))

    return cipher, decrypted_content


def sign_message(data_to_sign, digest_alg, sign_key,
                 use_signed_attributes=True):
    """Function signs the data and returns the generated ASN.1

    :param data_to_sign: A byte string of the data to be signed.

    :param digest_alg: 
        The digest algorithm to be used for generating the signature.

    :param sign_key: The key to be used for generating the signature.
    
    :param use_signed_attributes: Optional attribute to indicate weather the 
    CMS signature attributes should be included in the signature or not.

    :return: A CMS ASN.1 byte string of the signed data.    
    """

    if use_signed_attributes:
        digest_func = hashlib.new(digest_alg)
        digest_func.update(data_to_sign)
        message_digest = digest_func.digest()

        class SmimeCapability(core.Sequence):
            _fields = [
                ('0', core.Any, {'optional': True}),
                ('1', core.Any, {'optional': True}),
                ('2', core.Any, {'optional': True}),
                ('3', core.Any, {'optional': True}),
                ('4', core.Any, {'optional': True})
            ]

        class SmimeCapabilities(core.Sequence):
            _fields = [
                ('0', SmimeCapability),
                ('1', SmimeCapability, {'optional': True}),
                ('2', SmimeCapability, {'optional': True}),
                ('3', SmimeCapability, {'optional': True}),
                ('4', SmimeCapability, {'optional': True}),
                ('5', SmimeCapability, {'optional': True}),
            ]

        smime_cap = OrderedDict([
            ('0', OrderedDict([
                ('0', core.ObjectIdentifier('1.2.840.113549.3.7'))])),
            ('1', OrderedDict([
                ('0', core.ObjectIdentifier('1.2.840.113549.3.2')),
                ('1', core.Integer(128))])),
            ('2', OrderedDict([
                ('0', core.ObjectIdentifier('1.2.840.113549.3.4')),
                ('1', core.Integer(128))])),
        ])

        signed_attributes = cms.CMSAttributes([
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('content_type'),
                'values': cms.SetOfContentType([
                    cms.ContentType('data')
                ])
            }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('signing_time'),
                'values': cms.SetOfTime([
                    cms.Time({
                        'utc_time': core.UTCTime(datetime.now())
                    })
                ])
            }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('message_digest'),
                'values': cms.SetOfOctetString([
                    core.OctetString(message_digest)
                ])
            }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('1.2.840.113549.1.9.15'),
                'values': cms.SetOfAny([
                    core.Any(SmimeCapabilities(smime_cap))
                ])
            }),
        ])
        signature = asymmetric.rsa_pkcs1v15_sign(
            sign_key[0], signed_attributes.dump(), digest_alg)
    else:
        signed_attributes = None
        signature = asymmetric.rsa_pkcs1v15_sign(
            sign_key[0], data_to_sign, digest_alg)

    return cms.ContentInfo({
        'content_type': cms.ContentType('signed_data'),
        'content': cms.SignedData({
            'version': cms.CMSVersion('v1'),
            'digest_algorithms': cms.DigestAlgorithms([
                algos.DigestAlgorithm({
                    'algorithm': algos.DigestAlgorithmId(digest_alg)
                })
            ]),
            'encap_content_info': cms.ContentInfo({
                'content_type': cms.ContentType('data')
            }),
            'certificates': cms.CertificateSet([
                cms.CertificateChoices({
                    'certificate': sign_key[1].asn1
                })
            ]),
            'signer_infos': cms.SignerInfos([
                cms.SignerInfo({
                    'version': cms.CMSVersion('v1'),
                    'sid': cms.SignerIdentifier({
                        'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                            'issuer': sign_key[1].asn1[
                                'tbs_certificate']['issuer'],
                            'serial_number': sign_key[1].asn1[
                                'tbs_certificate']['serial_number']
                        })
                    }),
                    'digest_algorithm': algos.DigestAlgorithm({
                        'algorithm': algos.DigestAlgorithmId(digest_alg)
                    }),
                    'signed_attrs': signed_attributes,
                    'signature_algorithm': algos.SignedDigestAlgorithm({
                        'algorithm':
                            algos.SignedDigestAlgorithmId('rsassa_pkcs1v15')
                    }),
                    'signature': core.OctetString(signature)
                })
            ])
        })
    }).dump()


def verify_message(data_to_verify, signature, verify_cert):
    """Function parses an ASN.1 encrypted message and extracts/decrypts 
            the original message.

    :param data_to_verify: 
        A byte string of the data to be verified against the signature. 

    :param signature: A CMS ASN.1 byte string containing the signature.
    
    :param verify_cert: The certificate to be used for verifying the signature.

    :return: The digest algorithm that was used in the signature.    
    """

    cms_content = cms.ContentInfo.load(signature)
    digest_alg = None

    if cms_content['content_type'].native == 'signed_data':
        for signer in cms_content['content']['signer_infos']:

            signed_attributes = signer['signed_attrs'].copy()
            digest_alg = signer['digest_algorithm']['algorithm'].native

            if digest_alg not in DIGEST_ALGORITHMS:
                raise Exception('Unsupported Digest Algorithm')

            sig_alg = signer['signature_algorithm']['algorithm'].native
            sig = signer['signature'].native
            signed_data = data_to_verify

            if signed_attributes:
                attr_dict = {}
                for attr in signed_attributes.native:
                    attr_dict[attr['type']] = attr['values']

                message_digest = byte_cls()
                for d in attr_dict['message_digest']:
                    message_digest += d

                digest_func = hashlib.new(digest_alg)
                digest_func.update(data_to_verify)
                calc_message_digest = digest_func.digest()

                if message_digest != calc_message_digest:
                    raise IntegrityError('Failed to verify message signature: '
                                         'Message Digest does not match.')

                signed_data = signed_attributes.untag().dump()

            try:
                if sig_alg == 'rsassa_pkcs1v15':
                    asymmetric.rsa_pkcs1v15_verify(
                        verify_cert, sig, signed_data, digest_alg)
                elif sig_alg == 'rsassa_pss':
                    asymmetric.rsa_pss_verify(
                        verify_cert, sig, signed_data, digest_alg)
                else:
                    raise AS2Exception('Unsupported Signature Algorithm')
            except Exception as e:
                raise IntegrityError(
                    'Failed to verify message signature: {}'.format(e))

    return digest_alg
