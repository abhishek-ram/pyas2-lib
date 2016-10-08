import sys

PY2 = sys.version_info[0] == 2

if PY2:
    string_types = basestring,
    from email import message_from_string as parse_mime
    # from itertools import imap as map
else:
    string_types = str, bytes
    from email import message_from_bytes as parse_mime
    # map = map