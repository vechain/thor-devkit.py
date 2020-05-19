'''
Address

Address related operations and verifications.
'''

import re
from .keccak import keccak256


def remove_0x(address: str) -> str:
    ''' Remove the 0x if any. Returns the string without 0x '''
    if address.startswith("0x") or address.startswith("0X"):
        return address[2:]


def public_key_to_address(key_bytes: bytes) -> bytes:
    ''' Derive an address from a public key (uncompressed, starts with 0x04).

    Args:
        key_bytes (bytes): bytes that represent a public key.

    Returns:
        bytes: bytes that represents the address.
    '''
    # Get rid of the 0x04 (first byte) at the beginning.
    buffer = key_bytes[1:]
    return keccak256([buffer])[0][12:]


def is_address(address: str) -> bool:
    ''' Check if a text string is valid address.

    Args:
        address (str): The address string to be checked. 
        Should begin with '0x'.

    Returns:
        (bool): If it is valid address.
    '''

    c = re.compile('^0x[0-9a-f]{40}$', re.I)
    if c.match(address):
        return True
    else:
        return False


def to_checksum_address(address: str) -> str:
    ''' Turn address to checksum address that is compatible with eip-55

    Args:
        address (str): The address string to be checked.
        Should begin with '0x'.

    Returns:
        (str): The address that is properly capitalized.

    Raises:
        ValueError: If the address isn't a valid address itself.
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
