'''
Keystore Module.

Encrypt, decrypt and verify a keystore.

The "keystore" dict should contain following format:

{
    address: string
    crypto: object
    id: string
    version: number
}

'''
import re
import eth_keyfile

N = 131072  # aka. work_factor
P = 1
R = 8
DK_LEN = 32
SALT_LEN = 16


def encrypt(private_key: bytes, password: bytes) -> dict:
    '''
    Encrypt a private key to a keystore.
    The keystore is a json-style python dict.

    Parameters
    ----------
    private_key : bytes
        A private key in bytes.
    password : bytes
        A password.

    Returns
    -------
    dict
        A keystore
    '''
    return eth_keyfile.create_keyfile_json(private_key, password, 3, "scrypt", N)


def decrypt(keystore: dict, password: bytes) -> bytes:
    '''
    Decrypt a keystore into a private key (bytes).

    Parameters
    ----------
    keystore : dict
        A keystore.
    password : bytes
        A password.

    Returns
    -------
    bytes
        A private key in bytes.
    '''
    return eth_keyfile.decode_keyfile_json(keystore, password)


def _normalize(keystore: dict) -> dict:
    '''
    Normalize the keystore key:value pairs.
    Make each value in lower case.

    Parameters
    ----------
    keystore : dict
        A keystore.

    Returns
    -------
    dict
        A keystore.
    '''
    return keystore


ADDRESS_RE = re.compile('^[0-9a-f]{40}$', re.I)


def _validate(keystore: dict) -> bool:
    '''
    Validate the format of a key store.

    Parameters
    ----------
    keystore : dict
        A keystore.

    Returns
    -------
    bool
        True/False

    Raises
    ------
    ValueError
        If is not in good shape then throw.
    '''
    if keystore.get('version') != 3:
        raise ValueError('unsupported version {}'.format(keystore.version))

    if not ADDRESS_RE.match(keystore.get('address')):
        raise ValueError(
            'invalid address {}, should be 40 characters and alphanumero.'.format(keystore.address))

    if not keystore.get('id'):
        raise ValueError('Need "id" field.')

    if not keystore.get('crypto'):
        raise ValueError('Need "crypto" field.')

    return True


def well_formed(keystore: dict) -> bool:
    '''
    Validate if the keystore is in good shape (roughly).

    Parameters
    ----------
    keystore : dict
        A keystore.

    Returns
    -------
    bool
        True/False
    '''

    return _validate(keystore)
