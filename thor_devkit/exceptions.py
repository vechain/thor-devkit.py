from typing import Any, Optional

from rlp.exceptions import DeserializationError as DeserializationError  # noqa: F401
from rlp.exceptions import SerializationError as SerializationError  # noqa: F401


class DefaultTextExceptionMixin(BaseException):
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


class BadSignature(DefaultTextExceptionMixin, Exception):
    """The signature of certificate does not match with the signer."""


class BadTransaction(DefaultTextExceptionMixin, ValueError):
    """The decoded transaction is invalid."""
