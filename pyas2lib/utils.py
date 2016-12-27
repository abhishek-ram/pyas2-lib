from __future__ import absolute_import
from .compat import StringIO, BytesIO, CanonicalGenerator
from email import generator


def mime_to_string(msg, header_len):
    fp = StringIO()
    g = CanonicalGenerator(fp, maxheaderlen=header_len)
    g.flatten(msg)
    return fp.getvalue()


def mime_to_bytes(msg, header_len):
    fp = BytesIO()
    g = generator.BytesGenerator(fp, maxheaderlen=header_len)
    g.flatten(msg)
    return fp.getvalue()


def canonicalize(msg):
    return msg.replace('\r\n', '\n').replace('\r', '\n').replace('\n', '\r\n')
