'''
Blake2b

Blake2b hash function.
'''
import hashlib  # python3 lib/hashlib
from typing import List, Tuple


def blake2b256(list_of_bytes: List[bytes]) -> Tuple[bytes, int]:
    '''
    Computes a hash in black2b flavor, the output is 256 bits / 32 bytes.

    Parameters
    ----------
    list_of_bytes : List[bytes]
        The list of bytes, waited to be hashed.

    Returns
    -------
    Tuple[bytes, int]
        Hash result in bytes and the length of bytes (32).
    '''

    m = hashlib.blake2b(digest_size=32)
    for item in list_of_bytes:
        m.update(item)

    return m.digest(), m.digest_size
