from __future__ import absolute_import, unicode_literals

__all__ = [
    'ImproperlyConfigured', 'AS2Exception', 'MDNNotFound'
]


class ImproperlyConfigured(Exception):
    """
    Exception raised when the config passed to the client is inconsistent
    or invalid.
    """


class AS2Exception(Exception):
    """
    Base class for all exceptions raised by this package's operations (doesn't
    apply to :class:`~pyas2lib.ImproperlyConfigured`).
    """


class MDNNotFound(AS2Exception):
    """
    Raised when no MDN is found when parsing the received MIME message.
    """
