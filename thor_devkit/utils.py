"""Utils helping with hex<->string conversion and stripping."""
import sys
from typing import TypeVar, Union, cast

from .deprecation import renamed_function

if sys.version_info < (3, 8):
    from typing_extensions import Literal
else:
    from typing import Literal


_AnyBytes = Union[bytes, bytearray]


def strip_0x04(p: _AnyBytes) -> bytes:
    """Strip the 0x04 off the starting of a byte sequence."""
    if len(p) == 65 and p[0] == 4:
        return p[1:]
    else:
        return p


def remove_0x(address: str) -> str:
    """Remove the 0x prefix if any.

    Parameters
    ----------
    address : str
        Address string, like 0xabc...

    Returns
    -------
    str
        Address string without prefix "0x"
    """
    if address.startswith("0x") or address.startswith("0X"):
        return address[2:]
    else:
        return address


def validate_uncompressed_public_key(key_bytes: _AnyBytes) -> Literal[True]:
    """Check if bytes is the uncompressed public key.

    Parameters
    ----------
    key_bytes : bytes or bytearray
        Address in bytes.

    Returns
    -------
    Literal[True]
        Always ``True`` if public key is valid, raises otherwise.

    Raises
    ------
    ValueError
        If address doesn't begin with 04 as first byte.
    """
    if len(key_bytes) != 65:
        raise ValueError("Length should be 65 bytes.")

    if key_bytes[0] != 4:
        raise ValueError("Should begin with 04 as first byte.")

    return True


def is_valid_uncompressed_public_key(key_bytes: _AnyBytes) -> bool:
    try:
        return validate_uncompressed_public_key(key_bytes)
    except ValueError:
        return False


@renamed_function("validate_uncompressed_public_key")
def is_uncompressed_public_key(key_bytes: _AnyBytes) -> Literal[True]:
    return validate_uncompressed_public_key(key_bytes)


_T = TypeVar("_T")


def safe_tolowercase(s: _T) -> _T:
    if isinstance(s, str):
        # Cast, because mypy doesn't resolve TypeVar inside function body
        return cast(_T, s.lower())
    else:
        return s
