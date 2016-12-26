from __future__ import absolute_import, unicode_literals
from asn1crypto import cms, core, algos
from oscrypto import asymmetric, symmetric, util
import zlib


def compress_message(data_to_compress):
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
    })


def decompress_message(compressed_data, indefinite_length=False):
    der_bytes = compressed_data
    cms_content = cms.ContentInfo.load(der_bytes)
    decompressed_content = ''
    if cms_content['content_type'].native == 'compressed_data':
        if indefinite_length:
            encapsulated_data = cms_content['content']['encap_content_info'][
                'content'].native
            read = 0
            data = b''
            while read < len(encapsulated_data):
                value, read = core._parse_build(encapsulated_data, read)
                data += value.native
            decompressed_content = zlib.decompress(data)
        else:
            decompressed_content = cms_content['content'].decompressed

    return decompressed_content


def encrypt_message(data_to_encrypt, enc_alg, encryption_cert):
    enc_alg_list = enc_alg.split('_')
    cipher, key_length, mode = enc_alg_list[0], enc_alg_list[1], enc_alg_list[2]
    enc_alg_asn1, key, encrypted_content = None, None, None

    # Generate the symmetric encryption key and encrypt the message
    if cipher == 'tripledes':
        key = util.rand_bytes(int(key_length)/8)
        iv, encrypted_content = symmetric.tripledes_cbc_pkcs5_encrypt(
            key, data_to_encrypt, None)
        enc_alg_asn1 = algos.EncryptionAlgorithm({
            'algorithm': algos.EncryptionAlgorithmId('tripledes_3key'),
            'parameters': cms.OctetString(iv)
        })

    # Encrypt the key and build the ASN.1 message
    encrypted_key = asymmetric.rsa_pkcs1v15_encrypt(
        asymmetric.load_certificate(encryption_cert), key)

    return cms.ContentInfo({
        'content_type': cms.ContentType('enveloped_data'),
        'content': cms.EnvelopedData({
            'version': cms.CMSVersion('v0'),
            'recipient_infos': [
                cms.KeyTransRecipientInfo({
                    'version': cms.CMSVersion('v0'),
                    'rid': cms.RecipientIdentifier({
                        'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                            'issuer': encryption_cert[
                                'tbs_certificate']['issuer'],
                        'serial_number': encryption_cert[
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
    })


def decrypt_message(encrypted_data, decryption_key, indefinite_length=False):
    cms_content = cms.ContentInfo.load(encrypted_data)
    # print cms_content.debug()
    cipher, decrypted_content = None, None

    if cms_content['content_type'].native == 'enveloped_data':
        recipient_info = cms_content['content']['recipient_infos'][0].parse()
        key_enc_alg = recipient_info[
            'key_encryption_algorithm']['algorithm'].native
        encrypted_key = recipient_info['encrypted_key'].native
        if key_enc_alg == 'rsa':
            key = asymmetric.rsa_pkcs1v15_decrypt(decryption_key, encrypted_key)
            alg = cms_content['content']['encrypted_content_info'][
                'content_encryption_algorithm']
            encapsulated_data = cms_content['content'][
                'encrypted_content_info']['encrypted_content'].native
            if indefinite_length:
                read = 0
                data = b''
                while read < len(encapsulated_data):
                    value, read = core._parse_build(encapsulated_data, read)
                    data += value.native
            else:
                data = encapsulated_data

            if alg.encryption_cipher == 'tripledes':
                cipher = 'tripledes_192_cbc'
                decrypted_content = symmetric.tripledes_cbc_pkcs5_decrypt(
                    key, data, alg.encryption_iv)

    return cipher, decrypted_content
