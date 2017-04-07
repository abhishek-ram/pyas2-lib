from __future__ import unicode_literals, absolute_import
import sys

# Syntax sugar.
_ver = sys.version_info

#: Python 2.x?
is_py2 = (_ver[0] == 2)

#: Python 3.x?
is_py3 = (_ver[0] == 3)


if is_py2:
    str_cls = unicode  # noqa
    byte_cls = str
    int_types = (int, long)  # noqa
    from email import message_from_string as parse_mime
    from cStringIO import StringIO
    from cStringIO import StringIO as BytesIO
    from email.generator import Generator
    from email.generator import Generator as BytesGenerator

elif is_py3:
    str_cls = str
    byte_cls = bytes
    int_types = int
    from email import message_from_bytes as parse_mime
    from io import StringIO 
    from io import BytesIO 
    from email.generator import Generator, BytesGenerator
