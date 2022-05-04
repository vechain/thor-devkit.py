"""
Address Module.

VeChain "public key" and "address" related operations and verifications.
"""

import re
import sys

from thor_devkit.cry.keccak import keccak256
from thor_devkit.cry.utils import _AnyBytes, remove_0x, validate_uncompressed_public_key

if sys.version_info < (3, 8):
    from typing_extensions import Final
else:
    from typing import Final


ADDRESS_RE: Final = re.compile("^0x[0-9a-f]{40}$", re.I)


def public_key_to_address(key_bytes: _AnyBytes) -> bytes:
    """Derive an address from a public key.

    Parameters
    ----------
    key_bytes : bytes or bytearray
        public key (uncompressed, starts with 0x04).

    Returns
    -------
    bytes
        bytes that represents the address.
    """
    validate_uncompressed_public_key(key_bytes)
    # Get rid of the 0x04 (first byte) at the beginning.
    buffer = key_bytes[1:]
    # last 20 bytes from the 32 bytes hash.
    return keccak256([buffer])[0][12:]


def is_address(address: str) -> bool:
    """Check if a text string is valid address.

    Parameters
    ----------
    address : str
        The address string to be checked. Should begin with '0x'.

    Returns
    -------
    bool
        If it is valid address.
    """
    return bool(ADDRESS_RE.match(address))


def to_checksum_address(address: str) -> str:
    """Turn an address to a checksum address that is compatible with eip-55.

    Parameters
    ----------
    address : str
        The address string. Should begin with '0x'.

    Returns
    -------
    str
        The address that is properly capitalized.

    Raises
    ------
    ValueError
        If the address is not valid.
    """
    if not is_address(address):
        raise ValueError("The address is not valid.")

    body = remove_0x(address)  # remove '0x'.
    body = body.lower()

    h, _ = keccak256([body.encode("ascii")])
    hash_ = h.hex()

    parts = ["0x"]
    for idx, value in enumerate(body):
        if int(hash_[idx], 16) >= 8:
            parts.append(value.upper())
        else:
            parts.append(value)

    return "".join(parts)
