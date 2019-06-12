"""Module to test cms related features of pyas2lib."""
import pytest

from pyas2lib import cms
from pyas2lib.exceptions import (
    DecompressionError,
    DecryptionError,
    IntegrityError
)


INVALID_DATA = cms.cms.ContentInfo({
        'content_type': cms.cms.ContentType('data'),
}).dump()


def test_compress():
    """Test the compression and decompression functions."""
    compressed_data = cms.compress_message(b'data')
    assert cms.decompress_message(compressed_data) == b'data'

    with pytest.raises(DecompressionError):
        cms.decompress_message(INVALID_DATA)


def test_signing():
    """Test the signing and verification functions."""
    with pytest.raises(IntegrityError):
        cms.verify_message(b'data', INVALID_DATA, None)


def test_encryption():
    """Test the encryption and decryption functions."""
    with pytest.raises(DecryptionError):
        cms.decrypt_message(INVALID_DATA, None)
