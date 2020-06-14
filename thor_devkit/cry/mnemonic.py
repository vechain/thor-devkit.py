'''
Mnemonic Module.

Generate/Validate a words used for mnemonic wallet.

Derive the first private key from words.

Derive the correct seed for BIP32.
'''

from typing import List
from mnemonic import Mnemonic
from bip_utils import Bip32

# BIP-44 specified path notation:
# m / purpose' / coin_type' / account' / change / address_index

# Derive path for the VET:
# m / 44' / 818' / 0' / 0 /<address_index>
VET_PATH = "m/44'/818'/0'/0"


def _get_key_path(base_path: str, index: int = 0) -> str:
    return base_path.rstrip('/') + '/' + str(index)


def _get_vet_key_path(index: int = 0) -> str:
    return _get_key_path(VET_PATH, index)


def generate(strength: int = 128) -> List[str]:
    '''
    Generate BIP39 mnemonic words.

    Parameters
    ----------
    strength : int, optional
         Any of [128, 160, 192, 224, 256], by default 128

    Returns
    -------
    List[str]
        A list of words.

    Raises
    ------
    ValueError
        If the strength is not of correct length.
    '''
    if strength not in [128, 160, 192, 224, 256]:
        raise ValueError(
            'strength should be one of [128, 160, 192, 224, 256].')

    sentence = Mnemonic('english').generate(strength)

    return sentence.split(' ')


def validate(words: List[str]) -> bool:
    '''
    Check if the words form a valid BIP39 mnemonic words.

    Parameters
    ----------
    words : List[str]
        A list of english words.

    Returns
    -------
    bool
        True/False
    '''
    sentence = ' '.join(words)
    return Mnemonic('english').check(sentence)


def derive_seed(words: List[str]) -> bytes:
    '''
    Derive a seed from a word list.

    Parameters
    ----------
    words : List[str]
        A list of english words.

    Returns
    -------
    bytes
        64 bytes
    '''
    sentence = ' '.join(words)
    seed = Mnemonic.to_seed(sentence)  # bytes.
    return seed


def derive_private_key(words: List[str], index: int = 0) -> bytes:
    '''
    Get a private key from the mnemonic wallet,
    default to the 0 index of the deviration. (first key)

    Parameters
    ----------
    words : List[str]
        A list of english words.
    index : int, optional
        The private key index, first private key., by default 0

    Returns
    -------
    bytes
        [description]
    '''
    seed = derive_seed(words)
    bip32_ctx = Bip32.FromSeedAndPath(seed, _get_vet_key_path(index))
    return bip32_ctx.PrivateKey().Raw().ToBytes()
