"""Define utility functions used by the pyas2-lib package."""

import email
import random
import re
import sys
from datetime import datetime, timezone
from email import message
from email import policy
from email.generator import BytesGenerator
from io import BytesIO

from OpenSSL import crypto
from asn1crypto import pem

from pyas2lib.exceptions import AS2Exception


def unquote_as2name(quoted_name: str):
    """
    Function converts as2 name from quoted to unquoted format.

    :param quoted_name: the as2 name in quoted format
    :return: the as2 name in unquoted format
    """
    return email.utils.unquote(quoted_name)


def quote_as2name(unquoted_name: str):
    """
    Function converts as2 name from unquoted to quoted format.

    :param unquoted_name: the as2 name in unquoted format
    :return: the as2 name in unquoted format
    """

    if re.search(r'[\\" ]', unquoted_name, re.M):
        return '"' + email.utils.quote(unquoted_name) + '"'
    return unquoted_name


class BinaryBytesGenerator(BytesGenerator):
    """Override the bytes generator to better handle binary data."""

    def _handle_text(self, msg):
        """
        Handle writing the binary messages to prevent default behaviour of
        newline replacements.
        """
        if (
            msg.get_content_type() == "application/octet-stream"
            or msg.get("Content-Transfer-Encoding") == "binary"
        ):
            payload = msg.get_payload(decode=True)
            if payload is None:
                return
            self._fp.write(payload)
        else:
            super()._handle_text(msg)

    _writeBody = _handle_text


def mime_to_bytes(msg: message.Message, email_policy: policy.Policy = policy.HTTP):
    """
    Function to convert and email Message to flat string format.

    :param msg: email.Message to be converted to string
    :param email_policy: the policy to be used for flattening the message.
    :return: the byte string representation of the email message
    """
    fp = BytesIO()
    g = BinaryBytesGenerator(fp, policy=email_policy)
    g.flatten(msg)
    return fp.getvalue()


def canonicalize(email_message: message.Message):
    """
    Function to convert an email Message to standard format string/

    :param email_message: email.message.Message to be converted to standard string
    :return: the standard representation of the email message in bytes
    """

    if email_message.get("Content-Transfer-Encoding") == "binary":
        message_header = ""
        message_body = email_message.get_payload(decode=True)
        for k, v in email_message.items():
            message_header += "{}: {}\r\n".format(k, v)
        message_header += "\r\n"
        return message_header.encode("utf-8") + message_body

    return mime_to_bytes(email_message)


def make_mime_boundary(text: str = None):
    """
    Craft a random boundary.  If text is given, ensure that the chosen
    boundary doesn't appear in the text.
    """

    width = len(repr(sys.maxsize - 1))
    fmt = "%%0%dd" % width

    token = random.randrange(sys.maxsize)
    boundary = ("=" * 15) + (fmt % token) + "=="
    if text is None:
        return boundary
    b = boundary
    counter = 0
    while True:
        cre = re.compile("^--" + re.escape(b) + "(--)?$", re.MULTILINE)
        if not cre.search(text):
            break
        b = boundary + "." + str(counter)
        counter += 1
    return b


def extract_first_part(message_content: bytes, boundary: bytes):
    """Extract the first part of a multipart message."""
    first_message = message_content.split(boundary)[1].lstrip()
    if first_message.endswith(b"\r\n"):
        first_message = first_message[:-2]
    else:
        first_message = first_message[:-1]
    return first_message


def pem_to_der(cert: bytes, return_multiple: bool = True):
    """Convert a given certificate or list to PEM format."""
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
    return cert_list.pop()


def split_pem(pem_bytes: bytes):
    """
    Split a give PEM file with multiple certificates.

    :param pem_bytes: The pem data in bytes with multiple certs
    :return: yields a list of certificates contained in the pem file
    """
    started, pem_data = False, b""
    for line in pem_bytes.splitlines(False):

        if line == b"" and not started:
            continue

        if line[0:5] in (b"-----", b"---- "):
            if not started:
                started = True
            else:
                pem_data = pem_data + line + b"\r\n"
                yield pem_data

                started = False
                pem_data = b""

        if started:
            pem_data = pem_data + line + b"\r\n"


def verify_certificate_chain(cert_bytes, trusted_certs, ignore_self_signed=True):
    """Verify a given certificate against a trust store."""

    # Load the certificate
    certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bytes)

    # Create a certificate store and add your trusted certs
    try:
        store = crypto.X509Store()

        if ignore_self_signed:
            store.add_cert(certificate)

        # Assuming the certificates are in PEM format in a trusted_certs list
        for _cert in trusted_certs:
            store.add_cert(crypto.load_certificate(crypto.FILETYPE_ASN1, _cert))

        # Create a certificate context using the store and the certificate
        store_ctx = crypto.X509StoreContext(store, certificate)

        # Verify the certificate, returns None if certificate is not valid
        store_ctx.verify_certificate()

        return True

    except crypto.X509StoreContextError as e:
        raise AS2Exception(
            "Partner Certificate Invalid: %s" % e.args[-1][-1], "invalid-certificate"
        ) from e


def extract_certificate_info(cert: bytes):
    """
    Extract validity information from the certificate and return a dictionary.

    Provide either key with certificate (private) or public certificate.

    :param cert: the certificate as byte string in PEM or DER format
    :return: a dictionary holding certificate information:
                valid_from (datetime) - UTC
                valid_to (datetime) - UTC
                subject (list of name, value tuples)
                issuer (list of name, value tuples)
                serial (int)
    """
    # initialize the cert_info dictionary
    cert_info = {
        "valid_from": None,
        "valid_to": None,
        "subject": None,
        "issuer": None,
        "serial": None,
    }

    # get certificate to DER list
    der = pem_to_der(cert)

    # iterate through the list to find the certificate
    for _item in der:
        try:
            # load the certificate. if element is key, exception is triggered
            # and next element is tried
            certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, _item)

            # on successful load, extract the various fields into the dictionary
            cert_info["valid_from"] = datetime.strptime(
                certificate.get_notBefore().decode("utf8"), "%Y%m%d%H%M%SZ"
            ).replace(tzinfo=timezone.utc)
            cert_info["valid_to"] = datetime.strptime(
                certificate.get_notAfter().decode("utf8"), "%Y%m%d%H%M%SZ"
            ).replace(tzinfo=timezone.utc)
            cert_info["subject"] = [
                tuple(item.decode("utf8", "backslashreplace") for item in sets)
                for sets in certificate.get_subject().get_components()
            ]
            cert_info["issuer"] = [
                tuple(item.decode("utf8", "backslashreplace") for item in sets)
                for sets in certificate.get_issuer().get_components()
            ]
            cert_info["serial"] = certificate.get_serial_number()
            break
        except crypto.Error:
            continue

    # return the dictionary
    return cert_info


def normalize_digest_alg(digest_alg):
    """Normalizes digest algorithm to lower case as some systems send it upper case"""

    if not isinstance(digest_alg, str):
        return digest_alg

    return digest_alg.lower()
