"""Key store module.

Encrypt, decrypt and verify a key store.

The "keystore" dict should contain following format::

    {
        address: string
        crypto: object
        id: string
        version: number
    }
"""
import sys
from typing import Union

import eth_keyfile

from thor_devkit.cry.address import is_address
from thor_devkit.deprecation import renamed_function

if sys.version_info < (3, 8):
    from typing_extensions import Final, Literal, TypedDict
else:
    from typing import Final, Literal, TypedDict

__all__ = [
    "AES128CTRCipherParamsT",
    "PBKDF2ParamsT",
    "ScryptParamsT",
    "CryptoParamsT",
    "KeyStoreT",
    "encrypt",
    "decrypt",
    "validate",
    "is_valid",
]

SCRYPT_N: Final = 131072
"""Work factor for scrypt."""
SCRYPT_P: Final = 1
"""Parallelism factor for scrypt."""
SCRYPT_R: Final = 8
"""Block size for scrypt."""
DK_LEN: Final = 32
"""Derived key length for scrypt."""
SALT_LEN: Final = 16
"""Salt length for scrypt."""


class AES128CTRCipherParamsT(TypedDict):
    """Parameters for ``aes-128-ctr`` cipher.

    .. versionadded:: 2.0.0
    """

    iv: str
    """Internal parameter."""


class PBKDF2ParamsT(TypedDict):
    """Parameters for ``pbkdf2`` key derivation function.

    .. versionadded:: 2.0.0
    """

    c: int
    """Work factor."""
    dklen: int
    """Derived key length."""
    prf: Literal["hmac-sha256"]
    """Hash function to calculate HMAC"""
    salt: str
    """Salt to use."""


class ScryptParamsT(TypedDict):
    """Parameters for ``scrypt`` key derivation function.

    .. versionadded:: 2.0.0
    """

    dklen: int
    """Derived key length."""
    n: int
    """Work factor."""
    r: int
    """Block size."""
    p: int
    """Parallelism factor."""
    salt: str
    """Salt to use, 64 characters long (32 bytes)."""


class CryptoParamsT(TypedDict):
    """Type of ``crypto`` parameter of key store.

    .. versionadded:: 2.0.0
    """

    cipher: Literal["aes-128-ctr"]
    """Cipher used. ``aes-128-ctr`` is the only supported."""
    cipherparams: AES128CTRCipherParamsT
    """Parameters of used cipher."""
    ciphertext: str
    """Encoded data, 64 characters long (32 bytes)."""
    kdf: Literal["pbkdf2", "scrypt"]
    """Key derivation function (other are not supported)."""
    kdfparams: Union[PBKDF2ParamsT, ScryptParamsT]
    """Parameters of key derivation function."""
    mac: str
    """MAC (checksum variant), 64 characters long (32 bytes)."""


class KeyStoreT(TypedDict):
    """Type of key store body dictionary.

    .. versionadded:: 2.0.0
    """

    address: str
    """Address used."""
    id: str  # noqa: A003
    """36 chars, common format: ``x{8}-x{4}-x{4}-x{4}-x{12}``, ``x`` is any hex digit"""
    version: Literal[3]
    """Version used. Other are not supported."""
    crypto: CryptoParamsT
    """Cryptography parameters."""


def encrypt(private_key: bytes, password: Union[str, bytes]) -> KeyStoreT:
    """Encrypt a private key to a key store.

    Parameters
    ----------
    private_key : bytes
        A private key in bytes.
    password : bytes or str
        A password.

    Returns
    -------
    KeyStoreT
        A key store json-style dictionary.
    """
    return eth_keyfile.create_keyfile_json(private_key, password, 3, "scrypt", SCRYPT_N)


def decrypt(keystore: KeyStoreT, password: Union[str, bytes]) -> bytes:
    """Decrypt a keystore into a private key (bytes).

    Parameters
    ----------
    keystore : KeyStoreT
        A keystore dict.
    password : bytes or str
        A password.

    Returns
    -------
    bytes
        A private key in bytes.
    """
    return eth_keyfile.decode_keyfile_json(keystore, password)


def _normalize(keystore: KeyStoreT) -> KeyStoreT:
    """Normalize the key store key:value pairs.

    Parameters
    ----------
    keystore : KeyStoreT
        A key store dict.

    Returns
    -------
    KeyStoreT
        A key store dict (normalized).
    """
    return keystore


def _validate(keystore: KeyStoreT) -> Literal[True]:
    """Validate the format of a key store."""
    if keystore.get("version") != 3:
        raise ValueError("Unsupported version: {}".format(keystore.get("version")))

    if not is_address(keystore.get("address", "")):
        raise ValueError(
            "invalid address {}, should be 40 characters and alphanumeric.".format(
                keystore.get("address")
            )
        )

    if not keystore.get("id"):
        raise ValueError('Need "id" field.')

    if not keystore.get("crypto"):
        raise ValueError('Need "crypto" field.')

    return True


@renamed_function("validate")
def well_formed(keystore: KeyStoreT) -> Literal[True]:
    """[Deprecated] Validate if the key store is in good shape (roughly).

    .. deprecated:: 2.0.0
        Function :func:`well_formed` is deprecated for naming consistency.
        Use :func:`validate` or :func:`is_valid` instead.
    """
    return _validate(keystore)


def validate(keystore: KeyStoreT) -> Literal[True]:
    """Validate if the key store is in good shape (roughly).

    Parameters
    ----------
    keystore : KeyStoreT
        A key store dict.

    Returns
    -------
    Literal[True]
        Always ``True`` for valid key store, raises otherwise.

    Raises
    ------
    ValueError
        If data not in good shape.
    """
    # Extra "raises", because it is primary interface to private method that raises.
    return _validate(keystore)


def is_valid(keystore: KeyStoreT) -> bool:
    """Validate if the key store is in good shape (roughly).

    Parameters
    ----------
    keystore : KeyStoreT
        A key store dict.

    Returns
    -------
    bool
        Whether key store dict is well-formed.
    """
    try:
        return _validate(keystore)
    except ValueError:
        return False
