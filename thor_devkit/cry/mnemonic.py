"""Mnemonic-related utilities.

- Generate/validate a words used for mnemonic wallet.
- Derive the first private key from words.
- Derive the correct seed for BIP32_.

Documentation:

- HD wallets:
  `BIP32 <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>`_
- Mnemonic code:
  `BIP39 <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>`_
"""

import sys
from typing import Iterable, List, Tuple

try:
    from bip_utils import Bip32Secp256k1 as Bip32

    IS_OLD_BIP_UTILS = False
except ImportError:
    from bip_utils import Bip32

    IS_OLD_BIP_UTILS = True

from mnemonic import Mnemonic

from thor_devkit.deprecation import renamed_function

if sys.version_info < (3, 8):
    from typing_extensions import Final, Literal
else:
    from typing import Final, Literal
if sys.version_info < (3, 10):
    from typing_extensions import TypeAlias
else:
    from typing import TypeAlias

__all__ = [
    # Main
    "generate",
    "is_valid",
    "derive_seed",
    "derive_private_key",
    # Types
    "AllowedStrengthsT",
    # Schemas
    "ALLOWED_STRENGTHS",
]


AllowedStrengthsT: TypeAlias = Literal[128, 160, 192, 224, 256]
"""Allowed mnemonic strength literal type."""

ALLOWED_STRENGTHS: Final[Tuple[AllowedStrengthsT, ...]] = (128, 160, 192, 224, 256)
"""Allowed mnemonic strength options."""


def _get_key_path(base_path: str, index: int = 0) -> str:
    return base_path.rstrip("/") + "/" + str(index)


def _get_vet_key_path(index: int = 0) -> str:
    # Prevent circular import
    from thor_devkit.cry.hdnode import VET_EXTERNAL_PATH

    return _get_key_path(VET_EXTERNAL_PATH, index)


def generate(strength: AllowedStrengthsT = 128) -> List[str]:
    """Generate BIP39_ mnemonic words.

    Parameters
    ----------
    strength : int, default: 128
         Any of [128, 160, 192, 224, 256] (:const:`ALLOWED_STRENGTHS`)

    Returns
    -------
    List[str]
        A list of words.

    Raises
    ------
    ValueError
        If the strength is not allowed.
    """
    if strength not in ALLOWED_STRENGTHS:
        raise ValueError(f"strength should be one of {ALLOWED_STRENGTHS}.")

    sentence = Mnemonic("english").generate(strength)

    return sentence.split(" ")


def is_valid(words: Iterable[str]) -> bool:
    """Check if the words form a valid BIP39_ mnemonic words.

    .. versionadded:: 2.0.0

    Parameters
    ----------
    words : Iterable of str
        A list of english words.

    Returns
    -------
    bool
        Whether mnemonic is valid.
    """
    sentence = " ".join(words)
    return Mnemonic("english").check(sentence)


@renamed_function("is_valid")
def validate(words: Iterable[str]) -> bool:
    """Check if the words form a valid BIP39_ mnemonic phrase.

        .. customtox-exclude::

    .. deprecated:: 2.0.0
        Function :func:`validate` is deprecated for naming consistency.
        Use :func:`is_valid` instead. There is no raising equivalent.
    """
    return is_valid(words)


def derive_seed(words: Iterable[str]) -> bytes:
    """Derive a seed from a word list.

    Parameters
    ----------
    words : Iterable of str
        A list of english words.

    Returns
    -------
    bytes
        64 bytes

    Raises
    ------
    ValueError
        Seed phrase is malformed.
    """
    if not is_valid(words):
        raise ValueError("Input words doesn't pass validation check.")

    sentence = " ".join(words)
    return Mnemonic.to_seed(sentence)  # bytes.


def derive_private_key(words: Iterable[str], index: int = 0) -> bytes:
    """Get a private key from the mnemonic wallet.

    Parameters
    ----------
    words : Iterable of str
        A list of english words.
    index : int, default: 0
        The private key index, starting from zero.

    Returns
    -------
    bytes
        Private key.
    """
    seed = derive_seed(words)
    bip32_ctx = Bip32.FromSeedAndPath(seed, _get_vet_key_path(index))
    return bip32_ctx.PrivateKey().Raw().ToBytes()
