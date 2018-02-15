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
    from email.generator import Generator, NL, fcre, _make_boundary

    class BytesGenerator(Generator):

        def _handle_multipart(self, msg):
            # The trick here is to write out each part separately, merge the all
            # together, and then make sure that the boundary we've chosen isn't
            # present in the payload.
            msgtexts = []
            subparts = msg.get_payload()
            if subparts is None:
                subparts = []
            elif isinstance(subparts, basestring):
                # e.g. a non-strict parse of a message with no starting boundary
                self._fp.write(subparts)
                return
            elif not isinstance(subparts, list):
                # Scalar payload
                subparts = [subparts]
            for part in subparts:
                s = StringIO()
                g = self.clone(s)
                g.flatten(part, unixfrom=False)
                msgtexts.append(s.getvalue())
            # BAW: What about boundaries that are wrapped in double-quotes?
            boundary = msg.get_boundary()
            if not boundary:
                # Create a boundary that doesn't appear in any of the
                # message texts.
                alltext = NL.join(msgtexts)
                boundary = _make_boundary(alltext)
                msg.set_boundary(boundary)
            # If there's a preamble, write it out, with a trailing CRLF
            if msg.preamble is not None:
                if self._mangle_from_:
                    preamble = fcre.sub('>From ', msg.preamble)
                else:
                    preamble = msg.preamble
                print >> self._fp, preamble
            # dash-boundary transport-padding CRLF
            print >> self._fp, '--' + boundary
            # body-part
            if msgtexts:
                self._fp.write(msgtexts.pop(0))
            # *encapsulation
            # --> delimiter transport-padding
            # --> CRLF body-part
            for body_part in msgtexts:
                # delimiter transport-padding CRLF
                print >> self._fp, '\n--' + boundary
                # body-part
                self._fp.write(body_part)
            # close-delimiter transport-padding
            self._fp.write('\n--' + boundary + '--' + NL)
            if msg.epilogue is not None:
                if self._mangle_from_:
                    epilogue = fcre.sub('>From ', msg.epilogue)
                else:
                    epilogue = msg.epilogue
                self._fp.write(epilogue)

elif is_py3:
    str_cls = str
    byte_cls = bytes
    int_types = int
    from email import message_from_bytes as parse_mime
    from io import StringIO 
    from io import BytesIO 
    from email.generator import Generator, BytesGenerator
