"""Blake2b hash function."""
import hashlib  # python3 lib/hashlib
from typing import Iterable, Tuple

from ..utils import _AnyBytes


def blake2b256(list_of_bytes: Iterable[_AnyBytes]) -> Tuple[bytes, int]:
    """Compute a hash in black2b flavor.

    Parameters
    ----------
    list_of_bytes : Iterable of (bytes or bytearray)
        The iterable of `bytes` or `bytearray`'s to be hashed.

    Returns
    -------
    Tuple[bytes, int]
        Hash result in bytes (32 bytes) and the length of bytes (32).

    Raises
    ------
    TypeError
        If argument type is wrong.
    """
    if isinstance(list_of_bytes, (bytes, bytearray)):  # type: ignore[unreachable]
        raise TypeError(
            f"Expected iterable of bytes or bytearray's, got: {type(list_of_bytes)}"
        )

    m = hashlib.blake2b(digest_size=32)
    for item in list_of_bytes:
        m.update(item)

    return m.digest(), m.digest_size
