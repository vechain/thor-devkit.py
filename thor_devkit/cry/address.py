'''
Address Module.

VeChain "public key" and "address" related operations and verifications.
'''

import re
from .keccak import keccak256


def _remove_0x(address: str) -> str:
    '''
    Remove the 0x if any. Returns the string without 0x

    Parameters
    ----------
    address : str
        Address string, like 0xabc...

    Returns
    -------
    str
        Address string without prefix "0x"
    '''

    if address.startswith("0x") or address.startswith("0X"):
        return address[2:]


def _is_uncompressed_public_key(key_bytes: bytes) -> bool:
    '''
    Check if bytes is the uncompressed public key.

    Parameters
    ----------
    address : bytes
        Address in bytes. Should be 65 bytes.

    Returns
    -------
    bool
        True/False

    Raises
    ------
    ValueError
        If address isn't 65 bytes.
    ValueError
        If address doesn't begin with 04 as first byte.
    '''
    if len(key_bytes) != 65:
        raise ValueError('Length should be 65 bytes.')

    if key_bytes[0] != 4:
        raise ValueError('Should begin with 04 as first byte.')

    return True


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
    _is_uncompressed_public_key(key_bytes)
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

    body = _remove_0x(address)  # remove '0x'.
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
