from __future__ import absolute_import, unicode_literals
from asn1crypto import cms, pem
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

    try:
        compressed_data.encode('ascii')
    except UnicodeDecodeError:
        der_bytes = compressed_data
    else:
        der_bytes = pem.unarmor(
            '-----BEGIN PKCS7-----\r\n'
            '{}\r\n-----END PKCS7-----'.format(compressed_data))

    cms_content = cms.ContentInfo.load(der_bytes)
    if cms_content['content_type'].native == 'compressed_data':
        return cms_content['content'].decompressed
    else:
        return ''
