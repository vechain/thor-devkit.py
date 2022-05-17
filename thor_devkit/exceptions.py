"""Custom exceptions.

:exc:`DeserializationError` and :exc:`SerializationError` are aliases for
:exc:`rlp.exception.DeserializationError` and
:exc:`rlp.exception.SerializationError`
(they aren't listed on their
`documentation page <https://pyrlp.readthedocs.io/en/latest/>`_).
"""
from typing import Any, Optional

from rlp.exceptions import DeserializationError as DeserializationError
from rlp.exceptions import SerializationError as SerializationError

__all__ = [
    "DeserializationError",
    "SerializationError",
    "BadSignature",
    "BadTransaction",
]


class _DefaultTextExceptionMixin(BaseException):
    @property
    def _message(self) -> str:
        if self.__doc__:
            return self.__doc__
        raise NotImplementedError

    def __init__(
        self, message: Optional[str] = None, *args: Any, **kwargs: Any
    ) -> None:
        if message is None:
            message = self._message
        super().__init__(message, *args, **kwargs)


class BadSignature(_DefaultTextExceptionMixin, Exception):
    """The signature of certificate does not match with the signer."""


class BadTransaction(_DefaultTextExceptionMixin, ValueError):
    """The decoded transaction is invalid."""
