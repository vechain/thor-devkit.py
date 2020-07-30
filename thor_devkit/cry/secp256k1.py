'''
secp256k1 Elliptic Curve related functions.

1) Generate a private Key.
2) Derive uncompressed public key from private key.
3) Sign a message hash using the private key, generate signature.
4) Given the message hash and signature, recover the uncompressed public key.
'''

from ecdsa import SigningKey, SECP256k1
from eth_keys import KeyAPI


MAX = bytes.fromhex(
    'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')
ZERO = bytes.fromhex('0' * 64)


def _is_valid_private_key(priv_key: bytes) -> bool:
    '''
    Verify if a private key is good.

    Returns
    -------
    bool
        True if the private key is valid.
    '''
    if priv_key == ZERO:
        return False

    if priv_key >= MAX:
        return False
    
    if len(priv_key) != 32:
        return False

    return True


def _is_valid_message_hash(msg_hash: bytes) -> bool:
    '''
    Verify if a message hash is in correct format.
    (as in terms of VeChain)

    Parameters
    ----------
    msg_hash: bytes
        The msg hash to be processed.

    Returns
    -------
    bool
        If the message hash is in correct format or not.
    '''
    return len(msg_hash) == 32


def generate_privateKey() -> bytes:
    '''
    Create a random number(32 bytes) as private key.

    Returns
    -------
    bytes
        The private key in 32 bytes format.
    '''
    while True:
        _a = SigningKey.generate(curve=SECP256k1)
        if _is_valid_private_key(_a.to_string()):
            return _a.to_string()


def derive_publicKey(priv_key: bytes) -> bytes:
    '''
    Derive public key from a private key(uncompressed).

    Parameters
    ----------
    priv_key: bytes
        The private key in bytes.

    Returns
    -------
    bytes
        The public key(uncompressed) in bytes,
        which starts with 04.

    Raises
    ------
    ValueError
        If the private key is not valid.
    '''
    if not _is_valid_private_key(priv_key):
        raise ValueError('Private Key not valid.')

    _a = SigningKey.from_string(priv_key, curve=SECP256k1)
    return _a.verifying_key.to_string("uncompressed")


def sign(msg_hash: bytes, priv_key: bytes) -> bytes:
    '''
    Sign the message hash.
    (not the message itself)

    Parameters
    ----------
    msg_hash: bytes
        The message hash.
    priv_key: bytes
        The private key in bytes.

    Returns
    -------
    bytes
        The signing result.

    Raises
    ------
    ValueError
        If the input is malformed.
    '''
    if not _is_valid_message_hash(msg_hash):
        raise ValueError('Message hash not valid.')

    if not _is_valid_private_key(priv_key):
        raise ValueError('Private Key not valid.')

    sig = KeyAPI().ecdsa_sign(msg_hash, KeyAPI.PrivateKey(priv_key))

    r = sig.r.to_bytes(32, byteorder='big')
    s = sig.s.to_bytes(32, byteorder='big')
    v = sig.v.to_bytes(1, byteorder='big')  # public key recovery bit.

    return b''.join([r, s, v])  # 32 + 32 + 1 bytes


def recover(msg_hash: bytes, sig: bytes) -> bytes:
    '''
    Recover the uncompressed public key from signature.

    Parameters
    ----------
    msg_hash: bytes
        The message hash.
    sig: bytes
        The signature.

    Returns
    -------
    bytes
        public key in uncompressed format.

    Raises
    ------
    ValueError
        If the signature is bad,
        or recovery bit is bad,
        or cannot recover(sig and msg_hash doesn't match).
    '''

    if not _is_valid_message_hash(msg_hash):
        raise ValueError('Message Hash must be 32 bytes.')

    if len(sig) != 65:
        raise ValueError('Signature must be 65 bytes.')

    if not (sig[64] == 0 or sig[64] == 1):
        raise ValueError('Signature last byte must be 0 or 1')

    pk = KeyAPI().ecdsa_recover(
        msg_hash,
        KeyAPI.Signature(signature_bytes=sig)
    )

    # uncompressed should have first byte = 04
    return bytes([4]) + pk.to_bytes()
