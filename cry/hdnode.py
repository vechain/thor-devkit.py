'''
HD nodes, HD wallets.

Hierarchically Deterministic Wallets.

Relevant information: BIP32 and BIP44.
BIP32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
BIP44: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

'''
from typing import List


def from_mnemonic(words: List[str]):
    pass


def from_public_key(pub: bytes, chain_code: bytes):
    pass


def from_private_key(priv: bytes, chain_code: bytes):
    pass
