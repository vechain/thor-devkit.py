"""Blake2b hash function."""
import hashlib  # python3 lib/hashlib
from typing import Iterable, Tuple

__all__ = ["blake2b256"]


def blake2b256(list_of_bytes: Iterable[bytes]) -> Tuple[bytes, int]:
    """Compute a hash in black2b flavor.

    Parameters
    ----------
    list_of_bytes : Iterable of bytes
        The iterable of :class:`bytes` or :class:`bytearray`'s to be hashed.

    Returns
    -------
    Tuple[bytes, int]
        Hash result in :class:`bytes` (32 bytes) and the length of bytes (32).

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
