"""
Mnemonic Module.

Generate/Validate a words used for mnemonic wallet.

Derive the first private key from words.

Derive the correct seed for BIP32.
"""

import sys
from typing import Iterable, List, Tuple

from bip_utils import Bip32
from mnemonic import Mnemonic

from ..deprecation import renamed_function

if sys.version_info < (3, 8):
    from typing_extensions import Final, Literal, get_args
else:
    from typing import Final, Literal, get_args


_ALLOWED_STRENGTHS = Literal[128, 160, 192, 224, 256]
ALLOWED_STRENGTHS: Final[Tuple[_ALLOWED_STRENGTHS, ...]] = get_args(_ALLOWED_STRENGTHS)

# BIP-44 specified path notation:
# m / purpose' / coin_type' / account' / change / address_index

# Derive path for the VET:
# m / 44' / 818' / 0' / 0 /<address_index>
VET_PATH: Final = "m/44'/818'/0'/0"


def _get_key_path(base_path: str, index: int = 0) -> str:
    return base_path.rstrip("/") + "/" + str(index)


def _get_vet_key_path(index: int = 0) -> str:
    return _get_key_path(VET_PATH, index)


def generate(strength: _ALLOWED_STRENGTHS = 128) -> List[str]:
    """Generate BIP39 mnemonic words.

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
    """Check if the words form a valid BIP39 mnemonic words.

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
    """Check if the words form a valid BIP39 mnemonic phrase.

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
