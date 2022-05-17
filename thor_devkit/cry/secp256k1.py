"""Elliptic curve ``secp256k1`` related functions.

- Generate a private key.
- Derive uncompressed public key from private key.
- Sign a message hash using the private key, generate signature.
- Given the message hash and signature, recover the uncompressed public key.
"""
import sys

import eth_keys.exceptions
from ecdsa import SECP256k1, SigningKey
from eth_keys import KeyAPI

from thor_devkit.deprecation import renamed_function

if sys.version_info < (3, 8):
    from typing_extensions import Final, Literal
else:
    from typing import Final, Literal

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


def validate_private_key(priv_key: bytes) -> Literal[True]:
    """Validate given private key.

    .. versionadded:: 2.0.0

    Returns
    -------
    Literal[True]
        Always True.

    Raises
    ------
    ValueError
        If key is not valid.
    """
    try:
        priv_key = bytes(priv_key)
    except TypeError as e:
        raise ValueError("Given key is not convertible to bytes.") from e

    if priv_key == ZERO:
        raise ValueError("Private key must not be zero.")
    if priv_key >= MAX:
        raise ValueError("Private key must be less than MAX.")
    if len(priv_key) != 32:
        raise ValueError("Length of private key must be equal to 32.")
    return True


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
    try:
        return validate_private_key(priv_key)
    except ValueError:
        return False


def _validate_message_hash(msg_hash: bytes) -> Literal[True]:
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
    if not isinstance(msg_hash, bytes):
        raise ValueError("Message hash must be of type 'bytes'")
    if len(msg_hash) != 32:
        raise ValueError("Message hash must be 32 bytes long")
    return True


def generate_private_key() -> bytes:
    """Create a random number (32 bytes) as private key.

    .. versionadded:: 2.0.0

    Returns
    -------
    bytes
        The private key in 32 bytes format.
    """
    # We shouldn't measure coverage here, because situation "key is invalid"
    # is almost improbable
    while True:
        _a = SigningKey.generate(curve=SECP256k1).to_string()
        if is_valid_private_key(_a):  # pragma: no cover
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
    validate_private_key(priv_key)

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
    _validate_message_hash(msg_hash)
    validate_private_key(priv_key)

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
    _validate_message_hash(msg_hash)

    # This validates signature
    try:
        signature = KeyAPI.Signature(signature_bytes=sig)
    except (eth_keys.exceptions.BadSignature, eth_keys.exceptions.ValidationError) as e:
        raise ValueError("Signature is invalid.") from e

    pk = KeyAPI().ecdsa_recover(msg_hash, signature)

    # uncompressed should have first byte = 04
    return bytes([4]) + pk.to_bytes()
