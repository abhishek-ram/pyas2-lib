__all__ = [
    'ImproperlyConfigured', 'AS2Exception'
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