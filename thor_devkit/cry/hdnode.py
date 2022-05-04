"""
HD nodes, HD wallets.

Hierarchically Deterministic Wallets for VeChain.

Relevant information: BIP32 and BIP44.
BIP32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
BIP44: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

BIP-44 specified path notation:
m / purpose' / coin_type' / account' / change / address_index

Derive path for the VET:
m / 44' / 818' / 0' / 0 /<address_index>

So the following is the root of the "external" node chain for VET.

m / 44' / 818' / 0' / 0

m is the master key, which shall be generated from a seed.

The following is the "first" key pair on the "external" node chain.

m / 44' / 818' / 0' / 0 / 0

"""
import sys
from typing import Iterable

from bip_utils import Base58Encoder, Bip32
from eth_keys import KeyAPI

from ..utils import _AnyBytes, strip_0x04
from .address import public_key_to_address
from .mnemonic import derive_seed

if sys.version_info < (3, 8):
    from typing_extensions import Final
else:
    from typing import Final


VET_EXTERNAL_PATH: Final = "m/44'/818'/0'/0"

VERSION_MAINNET_PUBLIC: Final = bytes.fromhex("0488B21E")
VERSION_MAINNET_PRIVATE: Final = bytes.fromhex("0488ADE4")
DEPTH_MASTER_NODE: Final = bytes.fromhex("00")
FINGER_PRINT_MASTER_KEY: Final = bytes.fromhex("00000000")
CHILD_NUMBER_MASTER_KEY: Final = bytes.fromhex("00000000")


class HDNode:
    """
    HD Node that is able to derive child HD Node.

    Please use static methods provided in this class to construct
    new instances rather than instantiate one by hand.
    """

    def __init__(self, bip32_ctx: Bip32) -> None:
        """Class constructor, it is not recommended to use this directly.

        To construct an HDNode, use staticmethods below instead.

        Parameters
        ----------
        bip32_ctx : Bip32
            Context to build node from.
        """
        self.bip32_ctx = bip32_ctx

    @staticmethod
    def from_seed(seed: _AnyBytes, init_path: str = VET_EXTERNAL_PATH) -> "HDNode":
        """Construct an HD Node from a seed (64 bytes).

        Note
        ----
            The seed will be further developed into
            a "m" secret key and "chain code".

        Parameters
        ----------
        seed : bytes or bytearray
            Seed itself.
        init_path : str, default: :const:`VET_EXTERNAL_PATH`
            The initial derivation path

        Returns
        -------
        HDNode
            A new HDNode.
        """
        bip32_ctx = Bip32.FromSeedAndPath(seed, init_path)
        return HDNode(bip32_ctx)

    @staticmethod
    def from_mnemonic(
        words: Iterable[str], init_path: str = VET_EXTERNAL_PATH
    ) -> "HDNode":
        """Construct an HD Node from a mnemonic (set of words).

        Note
        ----
            The words will generate a seed,
            which will be further developed into
            a "m" secret key and "chain code".

        Parameters
        ----------
        words : Iterable of str
            Mnemonic words, usually 12 words.
        init_path : str, default: :const:`VET_EXTERNAL_PATH`
            The initial derivation path

        Returns
        -------
        HDNode
            A new HDNode.
        """
        seed = derive_seed(words)  # 64 bytes
        bip32_ctx = Bip32.FromSeedAndPath(seed, init_path)
        return HDNode(bip32_ctx)

    @staticmethod
    def from_public_key(pub: _AnyBytes, chain_code: _AnyBytes) -> "HDNode":
        """Construct an HD Node from an uncompressed public key.

        Parameters
        ----------
        pub : bytes or bytearray
            An uncompressed public key in bytes (starts with ``0x04`` as first byte).
        chain_code : bytes or bytearray
            32 bytes

        Returns
        -------
        HDNode
            A new HDNode.
        """
        all_bytes = b"".join(
            [
                VERSION_MAINNET_PUBLIC,
                DEPTH_MASTER_NODE,
                FINGER_PRINT_MASTER_KEY,
                CHILD_NUMBER_MASTER_KEY,
                chain_code,
                KeyAPI.PublicKey(strip_0x04(pub)).to_compressed_bytes(),
            ]
        )

        # double sha-256 checksum
        xpub_str = Base58Encoder.CheckEncode(all_bytes)
        bip32_ctx = Bip32.FromExtendedKey(xpub_str)
        return HDNode(bip32_ctx)

    @staticmethod
    def from_private_key(priv: _AnyBytes, chain_code: _AnyBytes) -> "HDNode":
        """
        Construct an HD Node from a private key.

        Parameters
        ----------
        priv : bytes or bytearray
            The private key in bytes.
        chain_code : bytes or bytearray
            32 bytes of random number you choose.

        Returns
        -------
        HDNode
            A new HDNode.
        """
        all_bytes = b"".join(
            [
                VERSION_MAINNET_PRIVATE,
                DEPTH_MASTER_NODE,
                FINGER_PRINT_MASTER_KEY,
                CHILD_NUMBER_MASTER_KEY,
                chain_code,
                b"\x00" + priv,
            ]
        )

        # double sha-256 checksum
        xpriv = Base58Encoder.CheckEncode(all_bytes)
        bip32_ctx = Bip32.FromExtendedKey(xpriv)

        return HDNode(bip32_ctx)

    def derive(self, index: int) -> "HDNode":
        """
        Derive the child HD Node from current HD Node.

        Possible derivation paths:
            * private key -> private key
            * private key -> public key
            * public key -> public key
            * public key -> private key (**impossible!**)

        Parameters
        ----------
        index : int
            Which key index (0,1,2... 2^32-1) to derive.

        Returns
        -------
        HDNode
            A New HDNode.
        """
        bip32_ctx = self.bip32_ctx.DerivePath(str(index))

        return HDNode(bip32_ctx)

    def public_key(self) -> bytes:
        """Get current node's public key in uncompressed format bytes.

        Returns
        -------
        bytes
            The uncompressed public key (starts with ``0x04``)
        """
        return b"\x04" + self.bip32_ctx.PublicKey().RawUncompressed().ToBytes()

    def private_key(self) -> bytes:
        """Get current node's private key in bytes format.

        Note
        ----
        If this node was publicly derived,
        then calling this function may cause a Bip32KeyError exception.

        Returns
        -------
        bytes
            The private key in bytes.
        """
        return self.bip32_ctx.PrivateKey().Raw().ToBytes()

    def chain_code(self) -> bytes:
        """Get the chaincode of current HD node.

        Returns
        -------
        bytes
            32 bytes of chain code.
        """
        return self.bip32_ctx.Chain()

    def address(self) -> bytes:
        """Get the common address format.

        Returns
        -------
        bytes
            The address in bytes. (without prefix 0x)
        """
        return public_key_to_address(self.public_key())

    def finger_print(self) -> bytes:
        """Get the finger print of current HD Node public key.

        Returns
        -------
        bytes
            finger print in bytes.
        """
        return self.bip32_ctx.FingerPrint()
