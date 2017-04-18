from __future__ import absolute_import, unicode_literals
from .compat import BytesIO, BytesGenerator, is_py2, _ver
import email
import re
import sys
import random


def unquote_as2name(quoted_name):
    return email.utils.unquote(quoted_name)


def quote_as2name(unquoted_name):
    if re.search(r'[\\" ]', unquoted_name, re.M):
        return '"' + email.utils.quote(unquoted_name) + '"'
    else:
        return unquoted_name


def mime_to_bytes(msg, header_len):
    fp = BytesIO()
    g = BytesGenerator(fp, maxheaderlen=header_len)
    g.flatten(msg)
    return fp.getvalue()


def canonicalize(message):

    if message.is_multipart() \
            or message.get('Content-Transfer-Encoding') != 'binary':

        return mime_to_bytes(message, 0).replace(
            b'\r\n', b'\n').replace(b'\r', b'\n').replace(b'\n', b'\r\n')
    else:
        message_header = ''
        message_body = message.get_payload(decode=True)
        for k, v in message.items():
            message_header += '{}: {}\r\n'.format(k, v)
        message_header += '\r\n'
        return message_header.encode('utf-8') + message_body


def make_mime_boundary(text=None):
    # Craft a random boundary.  If text is given, ensure that the chosen
    # boundary doesn't appear in the text.

    width = len(repr(sys.maxsize - 1))
    fmt = '%%0%dd' % width

    token = random.randrange(sys.maxsize)
    boundary = ('=' * 15) + (fmt % token) + '=='
    if text is None:
        return boundary
    b = boundary
    counter = 0
    while True:
        cre = re.compile('^--' + re.escape(b) + '(--)?$', re.MULTILINE)
        if not cre.search(text):
            break
        b = boundary + '.' + str(counter)
        counter += 1
    return b


def extract_first_part(message, boundary):
    """ Function to extract the first part of a multipart message"""
    first_message = message.split(boundary)[1].lstrip()
    if first_message.endswith(b'\r\n'):
        first_message = first_message[:-2]
    else:
        first_message = first_message[:-1]
    return first_message

