"""
Keystore Module.

Encrypt, decrypt and verify a keystore.

The "keystore" dict should contain following format::

    {
        address: string
        crypto: object
        id: string
        version: number
    }

"""
import sys
from typing import Any, Dict, Union

import eth_keyfile

from ..deprecation import renamed_function
from ..utils import _AnyBytes
from .address import is_address

if sys.version_info < (3, 8):
    from typing_extensions import Final, Literal, TypedDict
else:
    from typing import Final, Literal, TypedDict


SCRYPT_N: Final = 131072  # aka. work_factor
SCRYPT_P: Final = 1
SCRYPT_R: Final = 8
DK_LEN: Final = 32
SALT_LEN: Final = 16


class CryptoParamsT(TypedDict):
    cipher: str
    cipherparams: Dict[str, Any]
    ciphertext: str
    kdf: Literal["pbkdf2", "scrypt"]
    kdfparams: Dict[str, Any]
    mac: str


class KeyStoreT(TypedDict):
    address: str
    id: str  # noqa: A003
    version: int
    crypto: CryptoParamsT


def encrypt(private_key: _AnyBytes, password: Union[str, _AnyBytes]) -> KeyStoreT:
    """Encrypt a private key to a key store.

    Parameters
    ----------
    private_key : bytes or bytearray
        A private key in bytes.
    password : bytes or bytearray or str
        A password.

    Returns
    -------
    KeyStoreT
        A key store json-style dictionary.
    """
    return eth_keyfile.create_keyfile_json(private_key, password, 3, "scrypt", SCRYPT_N)


def decrypt(keystore: KeyStoreT, password: Union[str, _AnyBytes]) -> bytes:
    """Decrypt a keystore into a private key (bytes).

    Parameters
    ----------
    keystore : KeyStoreT
        A keystore dict.
    password : bytes or bytearray or str
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
    """Validate if the key store is in good shape (roughly).

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
    """  # noqa: DAR402
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
