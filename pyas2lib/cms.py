from __future__ import absolute_import, unicode_literals
from asn1crypto import cms, core
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


def decompress_message(compressed_data):

    der_bytes = compressed_data
    cms_content = cms.ContentInfo.load(der_bytes)
    decompressed_content = ''
    if cms_content['content_type'].native == 'compressed_data':
        try:
            decompressed_content = cms_content['content'].decompressed
        except:
            # If default decompression method fails then extract data manually
            # and then decompress
            encapsulated_data = cms_content['content']['encap_content_info'][
                'content'].native
            read = 0
            data = b''
            while read < len(encapsulated_data):
                value, read = core._parse_build(encapsulated_data, read)
                data += value.native
            decompressed_content = zlib.decompress(data)
    return decompressed_content


def decrypt_message(encrypted_data):
    cms_content = cms.ContentInfo.load(encrypted_data)
    print(cms_content.debug())
