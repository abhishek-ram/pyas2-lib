from __future__ import absolute_import
from __future__ import unicode_literals
import logging
from .compat import parse_mime

logger = logging.getLogger('pyas2lib')


class Message(object):
    """Class for building and parsing AS2 Inbound and Outbound Messages

    """

    _AS2_VERSION = '1.2'
    _MIME_VERSION = '1.0'
    _EDIINT_FEATURES = 'CMS'

    def __init__(self):
        self.organization = None
        self.partner = None
        self.payload = None
        self.content = None
        self.mic_content = None

    def build(self):
        pass

    def parse(self):
        pass
