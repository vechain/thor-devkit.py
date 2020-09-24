'''
Address Module.

VeChain "public key" and "address" related operations and verifications.
'''

import re
from .keccak import keccak256
from .utils import remove_0x, is_uncompressed_public_key


def public_key_to_address(key_bytes: bytes) -> bytes:
    '''
    Derive an address from a public key
    (uncompressed, starts with 0x04).

    Parameters
    ----------
    key_bytes : bytes
        bytes that represent a public key.

    Returns
    -------
    bytes
        bytes that represents the address.
    '''
    is_uncompressed_public_key(key_bytes)
    # Get rid of the 0x04 (first byte) at the beginning.
    buffer = key_bytes[1:]
    # last 20 bytes from the 32 bytes hash.
    return keccak256([buffer])[0][12:]


def is_address(address: str) -> bool:
    '''
    Check if a text string is valid address.

    Parameters
    ----------
    address : str
        The address string to be checked. Should begin with '0x'.

    Returns
    -------
    bool
        If it is valid address.
    '''

    c = re.compile('^0x[0-9a-f]{40}$', re.I)
    if c.match(address):
        return True
    else:
        return False


def to_checksum_address(address: str) -> str:
    '''
    Turn an address to a checksum address that is compatible with eip-55.

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
        If the address isn't a valid address itself.
    '''

    if not is_address(address):
        raise ValueError('The address is not valid.')

    body = remove_0x(address)  # remove '0x'.
    body = body.lower()

    h, _ = keccak256([body.encode("ascii")])
    hash = h.hex()

    parts = ['0x']
    for idx, value in enumerate(body):
        if int(hash[idx], 16) >= 8:
            parts.append(value.upper())
        else:
            parts.append(value)

    return ''.join(parts)
