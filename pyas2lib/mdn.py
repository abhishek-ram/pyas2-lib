from __future__ import absolute_import


class MDN(object):
    """Class for building and parsing AS2 Inbound and Outbound MDNs

    """

    def __init__(self):
        self.organization = None
        self.partner = None
        self.payload = None
        self.content = None
        self.mic_content = None

    def build(self):
        pass

    def parse_headers(self):
        pass

    def parse_body(self):
        pass
