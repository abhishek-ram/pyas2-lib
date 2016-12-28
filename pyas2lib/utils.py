from __future__ import absolute_import
from .compat import StringIO, BytesIO, CanonicalGenerator, CanonicalGenerator2


def mime_to_string(msg, header_len):
    fp = StringIO()
    g = CanonicalGenerator(fp, maxheaderlen=header_len)
    g.flatten(msg)
    return fp.getvalue()


def mime_to_bytes(msg, header_len):
    fp = BytesIO()
    g = CanonicalGenerator2(fp, maxheaderlen=header_len)
    g.flatten(msg)
    return fp.getvalue()


def canonicalize(msg):
    canonical_msg = ''
    for k, v in msg.items():
        canonical_msg += '{}: {}\r\n'.format(k, v)
    canonical_msg += '\r\n'

    return canonical_msg.encode('utf-8') + msg.get_payload(decode=True)    
