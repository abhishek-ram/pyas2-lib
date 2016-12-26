from __future__ import absolute_import, unicode_literals
from asn1crypto import cms, core
from oscrypto import asymmetric, symmetric
import zlib


def compress_message(data_to_compress):
    compressed_content = cms.ParsableOctetString(
        zlib.compress(data_to_compress))
    return cms.ContentInfo({
        'content_type': cms.ContentType('compressed_data'),
        'content': cms.CompressedData({
            'version': cms.CMSVersion(0),
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


def decrypt_message(encrypted_data, decryption_key, indefinite_length=False):
    cms_content = cms.ContentInfo.load(encrypted_data)
    decrypted_content = ''

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
                decrypted_content = symmetric.tripledes_cbc_pkcs5_decrypt(
                    key, data, alg.encryption_iv)

    return decrypted_content
