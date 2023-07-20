'''
Keccak

Keccak hash function.

Note:   Keccak is different from standard SHA3
        So the haslib.sha3_256() cannot be used to compute keccak_256()
'''

from eth_hash.auto import keccak
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
    m = keccak.new(b'')
    for item in list_of_bytes:
        m.update(item)

    _digest = m.digest()
    return _digest, len(_digest)