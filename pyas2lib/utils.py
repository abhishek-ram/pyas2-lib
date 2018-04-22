from __future__ import absolute_import, unicode_literals
from .compat import BytesIO, BytesGenerator, is_py2, _ver
from .exceptions import AS2Exception
from OpenSSL import crypto
from asn1crypto import pem
import email
import re
import sys
import random


def unquote_as2name(quoted_name):
    """
    Function converts as2 name from quoted to unquoted format

    :param quoted_name: the as2 name in quoted format
    :return: the as2 name in unquoted format
    """
    return email.utils.unquote(quoted_name)


def quote_as2name(unquoted_name):
    """
    Function converts as2 name from unquoted to quoted format
    :param unquoted_name: the as2 name in unquoted format
    :return: the as2 name in unquoted format
    """

    if re.search(r'[\\" ]', unquoted_name, re.M):
        return '"' + email.utils.quote(unquoted_name) + '"'
    else:
        return unquoted_name


def mime_to_bytes(msg, header_len):
    """
    Function to convert and email Message to flat string format
    :param msg: email.Message to be converted to string
    :param header_len: the msx length of the header per line
    :return: the byte string representation of the email message
    """
    fp = BytesIO()
    g = BytesGenerator(fp, maxheaderlen=header_len)
    g.flatten(msg)
    return fp.getvalue()


def canonicalize(message):
    """
    Function to convert an email Message to standard format string

    :param message: email.Message to be converted to standard string
    :return: the standard representation of the email message in bytes
    """

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


def pem_to_der(cert, return_multiple=True):
    """ Converts a given certificate or list to PEM format"""

    # initialize the certificate array
    cert_list = []

    # If certificate is in DER then un-armour it
    if pem.detect(cert):
        for _, _, der_bytes in pem.unarmor(cert, multiple=True):
            cert_list.append(der_bytes)
    else:
        cert_list.append(cert)

    # return multiple if return_multiple is set else first element
    if return_multiple:
        return cert_list
    else:
        return cert_list.pop()


def split_pem(pem_bytes):
    """
        Split a give PEM file with multiple certificates
    :param pem_bytes: The pem data in bytes with multiple certs
    :return: yields a list of certificates contained in the pem file
    """
    started, pem_data = False, b''
    for line in pem_bytes.splitlines(False):

        if line == b'' and not started:
            continue

        if line[0:5] in (b'-----', b'---- '):
            if not started:
                started = True
            else:
                pem_data = pem_data + line + b'\r\n'
                yield pem_data

                started = False
                pem_data = b''

        if started:
            pem_data = pem_data + line + b'\r\n'


def verify_certificate_chain(cert_str, trusted_certs, ignore_self_signed=True):
    """ Verify a given certificate against a trust store"""

    # Load the certificate
    certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_str)

    # Create a certificate store and add your trusted certs
    try:
        store = crypto.X509Store()

        if ignore_self_signed:
            store.add_cert(certificate)

        # Assuming the certificates are in PEM format in a trusted_certs list
        for _cert in trusted_certs:
            store.add_cert(
                crypto.load_certificate(crypto.FILETYPE_ASN1, _cert))

        # Create a certificate context using the store and the certificate
        store_ctx = crypto.X509StoreContext(store, certificate)

        # Verify the certificate, returns None if certificate is not valid
        store_ctx.verify_certificate()

        return True

    except crypto.X509StoreContextError as e:
        raise AS2Exception('Partner Certificate Invalid: %s' % e.args[-1][-1])
