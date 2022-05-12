"""Helper functions for :mod:`voluptuous` validation."""
import sys
import warnings
from typing import Callable, Optional, Union, overload

from voluptuous.error import Invalid

if sys.version_info < (3, 8):
    from typing_extensions import Literal
else:
    from typing import Literal

__all__ = ["hex_integer", "hex_string", "address_type"]


@overload
def hex_integer(
    length: Optional[int] = ...,
    *,
    to_int: Literal[False] = ...,
    require_prefix: bool = ...,
    allow_empty: bool = False,
) -> Callable[[str], str]:
    ...


@overload
def hex_integer(
    length: Optional[int] = None,
    *,
    to_int: Literal[True],
    require_prefix: bool = True,
    allow_empty: bool = False,
) -> Callable[[str], int]:
    ...


def hex_integer(
    length: Optional[int] = None,
    *,
    to_int: bool = False,
    require_prefix: bool = True,
    allow_empty: bool = False,
) -> Union[Callable[[str], str], Callable[[str], int]]:
    """Validate and normalize hex representation of number.

    Normalized form: ``0x{val}``, ``val`` is in lower case.

    Parameters
    ----------
    length: Optional[int]
        Expected length of string, excluding prefix.
    to_int: bool, default: False
        Normalize given string to integer.
    require_prefix: bool, default: True
        Require ``0x`` prefix.
    allow_empty: bool, default: False
        Allow empty string (or ``0x`` if ``require_prefix=True``)

    Returns
    -------
    Callable[[str], str]
        Validator callable.
    """
    assert not length or length >= 0, "Negative lengths not allowed."

    if length == 0 and not allow_empty:
        allow_empty = True
        warnings.warn(
            RuntimeWarning(
                "String with length=0 cannot be non-empty,"
                " pass allow_empty=True explicitly."
            )
        )

    def validate(value: str) -> Union[int, str]:
        if not isinstance(value, str):
            raise Invalid(f"Expected string, got: {type(value)}")

        value = value.lower()
        if not value.startswith("0x"):
            if require_prefix:
                raise Invalid('Expected hex string, that must start with "0x"')
        else:
            value = value[2:]

        real_length = len(value)
        if length is not None and real_length != length:
            raise Invalid(
                f"Expected hex representation of length {length}, got {real_length}"
            )

        try:
            int_value = int(value, 16)
        except ValueError as e:
            if allow_empty and value in {"", "0x"}:
                int_value = 0
            else:
                raise Invalid(
                    "Expected hex string, that is convertible to number"
                ) from e

        if to_int:
            return int_value

        return "0x" + value

    # We can define two functions in branches of ``to_int`` flag, but it will be
    # longer and less readable. Just ignore: we are sure that return is
    # either int or str depending on the flag.
    return validate  # type: ignore


@overload
def hex_string(
    length: Optional[int] = ...,
    *,
    to_bytes: Literal[False] = ...,
    allow_empty: bool = False,
    allow_prefix: bool = ...,
) -> Callable[[str], str]:
    ...


@overload
def hex_string(
    length: Optional[int] = None,
    *,
    to_bytes: Literal[True],
    allow_empty: bool = False,
    allow_prefix: bool = True,
) -> Callable[[str], bytes]:
    ...


def hex_string(
    length: Optional[int] = None,
    *,
    to_bytes: bool = False,
    allow_empty: bool = False,
    allow_prefix: bool = False,
) -> Union[Callable[[str], str], Callable[[str], bytes]]:
    """Validate and normalize hex representation of bytes (like :meth:`bytes.hex`).

    Normalized form: without ``0x`` prefix, in lower case.

    Parameters
    ----------
    length: Optional[int]
        Expected length of string.
    allow_empty: bool, default: False
        Allow empty string.
    allow_prefix: bool, default: True
        Allow ``0x`` prefix in input.

    Returns
    -------
    Callable[[str], str]
        Validator callable.
    """
    assert not length or length >= 0, "Negative lengths not allowed."

    if length == 0 and not allow_empty:
        allow_empty = True
        warnings.warn(
            RuntimeWarning(
                "String with length=0 cannot be non-empty,"
                " pass allow_empty=True explicitly."
            )
        )

    def validate(value: str) -> Union[bytes, str]:
        if not isinstance(value, str):
            raise Invalid(f"Expected string, got: {type(value)}")

        value = value.lower()
        if len(value) % 2:
            raise Invalid("Expected hex representation of even length")

        if value.startswith("0x"):
            if not allow_prefix:
                raise Invalid("Expected hex string without '0x' prefix.")
            value = value[2:]

        bytes_count = len(value)
        if length is not None and bytes_count != length:
            raise Invalid(
                f"Expected hex representation of length {length}, got {bytes_count}"
            )

        try:
            binary = bytes.fromhex(value)
        except ValueError as e:
            raise Invalid("Expected hex string, that is convertible to bytes") from e

        return binary if to_bytes else value

    # We can define two functions in branches od ``to_bytes`` flag, but it will be
    # longer and less readable. Just ignore: we are sure that return is
    # either int or str depending on the flag.
    return validate  # type: ignore


def address_type() -> Callable[[str], str]:
    """Validate and normalize address (40 bytes, with or without prefix).

    Returns
    -------
    Callable[[str], str]
        Validator callable.
    """

    def validate(value: str) -> str:
        base_validator = hex_integer(40, require_prefix=False)
        return base_validator(value)

    return validate
