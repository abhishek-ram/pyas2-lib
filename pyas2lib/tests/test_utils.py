"""Module to test the utility functions of pyas2lib."""
import datetime
import os
import pytest
from email.message import Message

from pyas2lib import utils
from pyas2lib.exceptions import AS2Exception
from pyas2lib.tests import TEST_DIR


def test_quoting():
    """Test the function for quoting and as2 name."""
    assert utils.quote_as2name('PYAS2LIB') == 'PYAS2LIB'
    assert utils.quote_as2name('PYAS2 LIB') == '"PYAS2 LIB"'


def test_bytes_generator():
    """Test the email bytes generator class."""
    message = Message()
    message.set_type('application/pkcs7-mime')
    assert utils.mime_to_bytes(message) == b'MIME-Version: 1.0\r\n' \
                                           b'Content-Type: application/pkcs7-mime\r\n\r\n'


def test_make_boundary():
    """Test the function for creating a boundary for multipart messages."""
    assert utils.make_mime_boundary(text='123456') is not None


def test_extract_first_part():
    """Test the function for extracting the first part of a multipart message."""
    message = b'header----first_part\n----second_part\n'
    assert utils.extract_first_part(message, b'----') == b'first_part'

    message = b'header----first_part\r\n----second_part\r\n'
    assert utils.extract_first_part(message, b'----') == b'first_part'


def test_cert_verification():
    """Test the verification of a certificate chain."""
    with open(os.path.join(TEST_DIR, 'cert_sb2bi_public.pem'), 'rb') as fp:
        certificate = utils.pem_to_der(fp.read(), return_multiple=False)

    with pytest.raises(AS2Exception):
        utils.verify_certificate_chain(
            certificate, trusted_certs=[], ignore_self_signed=False)


def test_extract_certificate_info():
    """ Test case that extracts data from private and public certificates
     in PEM or DER format"""

    cert_info = {
        'valid_from': datetime.datetime(2019, 6, 3, 11, 32, 57, tzinfo=datetime.timezone.utc),
        'valid_to': datetime.datetime(2029, 5, 31, 11, 32, 57, tzinfo=datetime.timezone.utc),
        'subject': [('C', 'AU'), ('ST', 'Some-State'), ('O', 'pyas2lib'), ('CN', 'test')],
        'issuer': [('C', 'AU'), ('ST', 'Some-State'), ('O', 'pyas2lib'), ('CN', 'test')],
        'serial': 13747137503594840569
    }
    cert_empty = {
        'valid_from': None,
        'valid_to': None,
        'subject': None,
        'issuer': None,
        'serial': None
    }

    # compare result of function with cert_info dict.
    with open(os.path.join(TEST_DIR, 'cert_extract_private.cer'), 'rb') as fp:
        assert utils.extract_certificate_info(fp.read()) == cert_info

    with open(os.path.join(TEST_DIR, 'cert_extract_private.pem'), 'rb') as fp:
        assert utils.extract_certificate_info(fp.read()) == cert_info

    with open(os.path.join(TEST_DIR, 'cert_extract_public.cer'), 'rb') as fp:
        assert utils.extract_certificate_info(fp.read()) == cert_info

    with open(os.path.join(TEST_DIR, 'cert_extract_public.pem'), 'rb') as fp:
        assert utils.extract_certificate_info(fp.read()) == cert_info

    assert utils.extract_certificate_info(b'') == cert_empty
