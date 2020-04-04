"""Module for defining the constants used by pyas2lib"""

AS2_VERSION = "1.2"

EDIINT_FEATURES = "CMS"

SYNCHRONOUS_MDN = "SYNC"
ASYNCHRONOUS_MDN = "ASYNC"

MDN_MODES = (SYNCHRONOUS_MDN, ASYNCHRONOUS_MDN)

MDN_CONFIRM_TEXT = (
    "The AS2 message has been successfully processed. "
    "Thank you for exchanging AS2 messages with pyAS2."
)

MDN_FAILED_TEXT = (
    "The AS2 message could not be processed. The "
    "disposition-notification report has additional details."
)

DIGEST_ALGORITHMS = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")
ENCRYPTION_ALGORITHMS = (
    "tripledes_192_cbc",
    "rc2_128_cbc",
    "rc4_128_cbc",
    "aes_128_cbc",
    "aes_192_cbc",
    "aes_256_cbc",
)
