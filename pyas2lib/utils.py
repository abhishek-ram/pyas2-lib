from __future__ import absolute_import, unicode_literals
from .compat import StringIO, BytesIO, CanonicalGenerator, CanonicalGenerator2
from uuid import uuid1


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


def canonicalize(message):
    message_header = ''
    if message.is_multipart():
        # # parts = []
        # message.set_boundary(uuid1())
        # message_boundary = ('--' + message.get_boundary()).encode('utf-8')
        # message_body = ''
        # for part in message.walk():
        #     if not part.is_multipart():
        #         part_header = ''
        #         for k, v in part.items():
        #             part_header += '{}: {}\n'.format(k, v)
        #         part_header += '\n'
        #         print part.as_string()
        #         message_body += \
        #             message_boundary + \
        #             part_header.encode('utf-8') + \
        #             part.get_payload(decode=True)
        # message_body += message_boundary + '--'.encode('utf-8')
        # print message_body
        # message.set_boundary(uuid1())
        # message_boundary = '--' + message.get_boundary()
        # message_body = message_boundary + message_boundary.join(parts)
        message_body = mime_to_bytes(message, 0)
    else:
        message_body = message.get_payload(decode=True)
    for k, v in message.items():
        message_header += '{}: {}\r\n'.format(k, v)
    message_header += '\r\n'
    return message_header.encode('utf-8') + message_body
