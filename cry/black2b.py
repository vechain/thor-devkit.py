import hashlib # python3 lib/hashlib
from typing import List, Tuple

def black2b256(list_of_bytes: List[bytes]) -> Tuple[bytes, int]:
    '''Computes black2b flavor hash, output 256 bits / 32 bytes.

    Args:
        list_of_bytes: A list of bytes.

    Returns:
        (bytes, int): Hash value in bytes and length of bytes.

    '''

    m = hashlib.blake2b(digest_size=32)
    for item in list_of_bytes:
        m.update(item)
    
    return m.digest(), m.digest_size