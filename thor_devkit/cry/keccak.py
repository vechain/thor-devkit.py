"""Keccak hash function."""
from typing import Iterable, Tuple

import sha3  # pysha3

__all__ = ["keccak256"]


def keccak256(list_of_bytes: Iterable[bytes]) -> Tuple[bytes, int]:
    """Compute the sha3_256 flavor hash.

    Parameters
    ----------
    list_of_bytes : Iterable of bytes
        A list of bytes to be hashed.

    Returns
    -------
    Tuple[bytes, int]
        Hash value in :class:`bytes` (32 bytes) and length of bytes.

    Raises
    ------
    TypeError
        If ``bytes`` or ``bytearray`` is used instead of sequence as input.
    """
    if isinstance(list_of_bytes, (bytes, bytearray)):  # type: ignore[unreachable]
        raise TypeError(
            f"Expected sequence of bytes or bytearray's, got: {type(list_of_bytes)}"
        )

    m = sha3.keccak_256()
    for item in list_of_bytes:
        m.update(item)

    return m.digest(), m.digest_size
