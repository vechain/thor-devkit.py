'''
Keccak

Keccak hash function.
'''

import sha3  # pysha3
from typing import List, Tuple


def keccak256(list_of_bytes: List[bytes]) -> Tuple[bytes, int]:
    '''
    Compute the sha3_256 flavor hash, outputs 256 bits / 32 bytes.

    Parameters
    ----------
    list_of_bytes : List[bytes]
        A list of bytes to be hashed.

    Returns
    -------
    Tuple[bytes, int]
        Hash value in bytes and length of bytes.
    '''
    m = sha3.keccak_256()
    for item in list_of_bytes:
        m.update(item)

    return m.digest(), m.digest_size
