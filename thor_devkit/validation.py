"""Helper functions for :mod:`voluptuous` validation."""
import sys
import warnings
from typing import Callable, Optional, Union, overload

from voluptuous.error import Invalid

from thor_devkit.cry.address import is_address

if sys.version_info < (3, 8):
    from typing_extensions import Literal
else:
    from typing import Literal


@overload
def hex_integer(
    length: Optional[int] = ...,
    *,
    expect_prefix: bool = ...,
    to_int: Literal[False] = ...,
    allow_empty: bool = False,
) -> Callable[[str], str]:
    ...


@overload
def hex_integer(
    length: Optional[int] = None,
    *,
    to_int: Literal[True],
    expect_prefix: bool = True,
    allow_empty: bool = False,
) -> Callable[[str], int]:
    ...


def hex_integer(
    length: Optional[int] = None,
    *,
    to_int: bool = False,
    expect_prefix: bool = True,
    allow_empty: bool = False,
) -> Union[Callable[[str], str], Callable[[str], int]]:
    """Validate and normalize hex representation of number.

    Parameters
    ----------
    length: Optional[int]
        Expected length of string, excluding prefix.
    to_int: bool, default: False
        Normalize given string to integer.
    expect_prefix: bool, default: True
        Require ``0x`` prefix.
    allow_empty: bool, default: False
        Allow empty string (or ``0x`` if ``expect_prefix=True``)

    Returns
    -------
    Callable[[str], str]
        Validator callable.
    """
    if length == 0 and not allow_empty:
        allow_empty = True
        warnings.warn(
            RuntimeWarning(
                "String with length=0 cannot be non-empty,"
                " pass allow_empty=True explicitly."
            )
        )

    def validate(value: str) -> Union[int, str]:
        no_prefix = False

        if not isinstance(value, str):
            raise Invalid(f"Expected string, got: {type(value)}")
        if not value.startswith("0x") and not value.startswith("0X"):
            if expect_prefix:
                raise Invalid('Expected hex string, that must start with "0x"')
            else:
                no_prefix = True

        real_length = len(value) if no_prefix else len(value) - 2
        if length is not None and real_length != length:
            raise Invalid(
                f"Expected hex representation of length {length}, got {real_length}"
            )

        try:
            int_value = int(value, 16)
        except ValueError as e:
            if allow_empty and value in {"", "0x", "0X"}:
                int_value = 0
            else:
                raise Invalid(
                    "Expected hex string, that is convertible to number"
                ) from e

        if to_int:
            return int_value

        return "0x" + (value if no_prefix else value[2:]).lower()

    # We can define two functions in branches od ``to_int`` flag, but it will be
    # longer and less readable. Just ignore: we are sure that return is
    # either int or str depending on the flag.
    return validate  # type: ignore


def hex_string(
    length: Optional[int] = None, *, allow_empty: bool = False
) -> Union[Callable[[str], str], Callable[[str], int]]:
    """Validate and normalize hex representation of bytes (like :meth:`bytes.hex`).

    Parameters
    ----------
    length: Optional[int]
        Expected length of string.
    allow_empty: bool, default: False
        Allow empty string.

    Returns
    -------
    Callable[[str], str]
        Validator callable.
    """
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

        if len(value) % 2:
            raise Invalid("Expected hex representation of even length")

        bytes_count = len(value)
        if length is not None and bytes_count != length:
            raise Invalid(
                f"Expected hex representation of length {length}, got {bytes_count}"
            )

        try:
            bytes.fromhex(value)
        except ValueError as e:
            raise Invalid("Expected hex string, that is convertible to bytes") from e

        return value.lower()

    # We can define two functions in branches od ``to_int`` flag, but it will be
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
        base_validator = hex_integer(40, expect_prefix=False)
        validated = base_validator(value)
        if not is_address(validated):
            raise Invalid("Given string is not an address.")
        return validated

    return validate
