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
    from email.generator import Generator as BytesGenerator
    from email.generator import _is8bitstring
    from email.header import Header

    class CanonicalGenerator(BytesGenerator):

        def _write_headers(self, msg):
            for h, v in msg.items():
                print >> self._fp, '%s:' % h,
                if self._maxheaderlen == 0:
                    # Explicit no-wrapping
                    print >> self._fp, '%s\r' % v
                elif isinstance(v, Header):
                    # Header instances know what to do
                    print >> self._fp, '%s\r' % v.encode()
                elif _is8bitstring(v):
                    # If we have raw 8bit data in a byte string, we have no idea
                    # what the encoding is.  There is no safe way to split this
                    # string.  If it's ascii-subset, then we could do a normal
                    # ascii split, but if it's multibyte then we could break the
                    # string.  There's no way to know so the least harm seems to
                    # be to not split the string and risk it being too long.
                    print >> self._fp, '%s\r' % v
                else:
                    # Header's got lots of smarts, so use it.  Note that this is
                    # fundamentally broken though because we lose idempotency when
                    # the header string is continued with tabs.  It will now be
                    # continued with spaces.  This was reversedly broken before we
                    # fixed bug 1974.  Either way, we lose.
                    print >> self._fp, '%s\r' % Header(
                        v, maxlinelen=self._maxheaderlen,
                        header_name=h).encode()
            # A blank line always separates headers from body
            print >> self._fp, '\r'

    CanonicalGenerator2 = CanonicalGenerator

else:
    str_cls = str
    byte_cls = bytes
    int_types = int
    from email import message_from_bytes as parse_mime
    from io import StringIO 
    from io import BytesIO 
    from email.generator import Generator, BytesGenerator
    from email.policy import default

    policy_8bit = default.clone(cte_type='8bit')

    class CanonicalGenerator(Generator):

        def _write_headers(self, msg):
            for h, v in msg.raw_items():
                lines = v.splitlines()
                self.write(h + ': ' + '\r\n'.join(lines) + '\r\n')
            self.write('\r\n')
 
    class CanonicalGenerator2(BytesGenerator):

        def __init__(self, *args, **kwargs):
            BytesGenerator.__init__(self, policy=policy_8bit, *args, **kwargs)
        
        def _write_headers(self, msg):
            for h, v in msg.raw_items():
                lines = v.splitlines()
                self._fp.write(
                    (h + ': ' + '\r\n'.join(lines) + '\r\n').encode('utf-8'))
            self._fp.write('\r\n'.encode('utf-8'))
