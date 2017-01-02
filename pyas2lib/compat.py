from __future__ import unicode_literals, absolute_import
import sys

PY2 = sys.version_info[0] == 2

if PY2:
    str_cls = unicode  # noqa
    byte_cls = str
    int_types = (int, long)  # noqa
    from email import message_from_string as parse_mime
    from cStringIO import StringIO
    from cStringIO import StringIO as BytesIO
    from email.generator import Generator
    from email.generator import Generator as BytesGenerator

else:
    str_cls = str
    byte_cls = bytes
    int_types = int
    from email import message_from_bytes as parse_mime
    from io import StringIO 
    from io import BytesIO 
    from email.generator import Generator, BytesGenerator
