''' Utils helping with hex<->string conversion and stripping '''


def strip_0x04(p: bytes):
    ''' Strip the 0x04 off the starting of a byte sequence.'''
    if len(p) == 65 and p[0] == 4:
        return p[1:]
    else:
        return p


def remove_0x(address: str) -> str:
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
    else:
        return address


def is_uncompressed_public_key(key_bytes: bytes) -> bool:
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
