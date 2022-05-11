"""Elliptic curve ``secp256k1`` related functions.

- Generate a private key.
- Derive uncompressed public key from private key.
- Sign a message hash using the private key, generate signature.
- Given the message hash and signature, recover the uncompressed public key.
"""
import sys

from ecdsa import SECP256k1, SigningKey
from eth_keys import KeyAPI

from thor_devkit.deprecation import renamed_function

if sys.version_info < (3, 8):
    from typing_extensions import Final
else:
    from typing import Final

__all__ = [
    "is_valid_private_key",
    "generate_private_key",
    "derive_public_key",
    "sign",
    "recover",
]

MAX: Final = bytes.fromhex(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
)
"""Maximal allowed private key."""

ZERO: Final = bytes(32)
"""32-bit zero in bytes form."""


def _is_valid_private_key(priv_key: bytes) -> bool:
    priv_key = bytes(priv_key)

    if priv_key == ZERO:
        return False

    if priv_key >= MAX:
        return False

    return len(priv_key) == 32


def is_valid_private_key(priv_key: bytes) -> bool:
    """Verify if a private key is well-formed.

    .. versionadded:: 2.0.0

    Parameters
    ----------
    priv_key : bytes
        Private key to check.

    Returns
    -------
    bool
        True if the private key is valid.
    """
    return _is_valid_private_key(priv_key)


def _is_valid_message_hash(msg_hash: bytes) -> bool:
    """Verify if a message hash is in correct format (as in terms of VeChain).

    Parameters
    ----------
    msg_hash : bytes
        The message hash to be processed.

    Returns
    -------
    bool
        Whether the message hash is in correct format.
    """
    return len(msg_hash) == 32


def generate_private_key() -> bytes:
    """Create a random number (32 bytes) as private key.

    .. versionadded:: 2.0.0

    Returns
    -------
    bytes
        The private key in 32 bytes format.
    """
    while True:
        _a = SigningKey.generate(curve=SECP256k1).to_string()
        if is_valid_private_key(_a):
            return _a


@renamed_function("generate_private_key")
def generate_privateKey() -> bytes:  # noqa: N802
    """Create a random number (32 bytes) as private key.

    .. customtox-exclude::

    .. deprecated:: 2.0.0
        Use :func:`generate_private_key` instead for naming consistency.
    """
    return generate_private_key()


def derive_public_key(priv_key: bytes) -> bytes:
    """Derive public key from a private key(uncompressed).

    .. versionadded:: 2.0.0

    Parameters
    ----------
    priv_key : bytes
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
    """
    if not is_valid_private_key(priv_key):
        raise ValueError("Private key not valid.")

    _a = SigningKey.from_string(priv_key, curve=SECP256k1)
    return _a.verifying_key.to_string("uncompressed")


@renamed_function("generate_public_key")
def derive_publicKey(priv_key: bytes) -> bytes:  # noqa: N802
    """Create a random number (32 bytes) as public key.

    .. customtox-exclude::

    .. deprecated:: 2.0.0
        Use :func:`derive_public_key` instead for naming consistency.
    """
    return derive_public_key(priv_key)


def sign(msg_hash: bytes, priv_key: bytes) -> bytes:
    """Sign the message hash.

    Note
    ----
    It signs **message hash**, not the message itself!

    Parameters
    ----------
    msg_hash : bytes
        The message hash.
    priv_key : bytes
        The private key in bytes.

    Returns
    -------
    bytes
        The signing result.

    Raises
    ------
    ValueError
        If the input is malformed.
    """
    if not _is_valid_message_hash(msg_hash):
        raise ValueError("Message hash not valid.")

    if not is_valid_private_key(priv_key):
        raise ValueError("Private Key not valid.")

    sig = KeyAPI().ecdsa_sign(msg_hash, KeyAPI.PrivateKey(priv_key))

    r = sig.r.to_bytes(32, byteorder="big")
    s = sig.s.to_bytes(32, byteorder="big")
    v = sig.v.to_bytes(1, byteorder="big")  # public key recovery bit.

    return b"".join([r, s, v])  # 32 + 32 + 1 bytes


def recover(msg_hash: bytes, sig: bytes) -> bytes:
    """Recover the uncompressed public key from signature.

    Parameters
    ----------
    msg_hash : bytes
        The message hash.
    sig : bytes
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
    """
    if not _is_valid_message_hash(msg_hash):
        raise ValueError("Message Hash must be 32 bytes.")

    if len(sig) != 65:
        raise ValueError("Signature must be 65 bytes.")

    if sig[-1] not in {0, 1}:
        raise ValueError("Signature last byte must be 0 or 1")

    pk = KeyAPI().ecdsa_recover(msg_hash, KeyAPI.Signature(signature_bytes=sig))

    # uncompressed should have first byte = 04
    return bytes([4]) + pk.to_bytes()
