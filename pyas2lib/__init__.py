from __future__ import absolute_import
import sys
from pyas2lib.as2 import DIGEST_ALGORITHMS, ENCRYPTION_ALGORITHMS,\
    MDN_CONFIRM_TEXT, MDN_FAILED_TEXT, Partner, Organization, Message, MDN

VERSION = (1, 0, 0)
__version__ = VERSION
__versionstr__ = '.'.join(map(str, VERSION))

__all__ = [
    'VERSION',
    'DIGEST_ALGORITHMS',
    'ENCRYPTION_ALGORITHMS',
    'MDN_CONFIRM_TEXT',
    'MDN_FAILED_TEXT',
    'Partner',
    'Organization',
    'Message',
    'MDN'
]

if (2, 7) <= sys.version_info < (3, 2):
    # On Python 2.7 and Python3 < 3.2, install no-op handler to silence
    # `No handlers could be found for logger "elasticsearch"` message per
    # <https://docs.python.org/2/howto/logging.html#configuring-logging-for-a-library>
    import logging
    logger = logging.getLogger('pyas2lib')
    logger.addHandler(logging.NullHandler())
