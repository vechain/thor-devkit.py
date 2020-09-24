'''
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

'''
from typing import List
from .mnemonic import derive_seed
from .address import public_key_to_address
from .utils import strip_0x04
from bip_utils import Bip32, Bip32Utils, Base58Encoder
from eth_keys import KeyAPI


VET_EXTERNAL_PATH = "m/44'/818'/0'/0"

VERSION_MAINNET_PUBLIC = bytes.fromhex('0488B21E')
VERSION_MAINNET_PRIVATE = bytes.fromhex('0488ADE4')
DEPTH_MASTER_NODE = bytes.fromhex('00')
FINGER_PRINT_MASTER_KEY = bytes.fromhex('00000000')
CHILD_NUMBER_MASTER_KEY = bytes.fromhex('00000000')


class HDNode():
    '''
    HD Node that is able to derive child HD Node.

    Please use static methods provided in this class to construct
    new instances rather than instantiate one by hand.
    '''

    def __init__(self, bip32_ctx: Bip32):
        '''
        HDNode constructor, it is not recommended to use this directly.
        To construct an HDNode, use staticmethods below instead.

        Parameters
        ----------
        bip32_ctx : Bip32
        '''

        self.bip32_ctx = bip32_ctx

    @staticmethod
    def from_seed(seed: bytes, init_path=VET_EXTERNAL_PATH):
        '''
        Construct an HD Node from a seed (64 bytes).
        The init_path is m/44'/818'/0'/0 for starting.
        or you can simply put in 44'/818'/0'/0

        Note
        ----
            The seed will be further developed into
            a "m" secret key and "chain code".

        Parameters
        ----------
        seed : bytes
            Seed itself.
        init_path : str, optional
            The derive path, by default VET_EXTERNAL_PATH

        Returns
        -------
        HDNode
            A new HDNode.
        '''
        bip32_ctx = Bip32.FromSeedAndPath(seed, init_path)
        return HDNode(bip32_ctx)

    @staticmethod
    def from_mnemonic(words: List[str], init_path=VET_EXTERNAL_PATH):
        '''
        Construct an HD Node from a set of words.
        The init_path is m/44'/818'/0'/0 by default on VeChain.

        Note
        ----
            The words will generate a seed,
            which will be further developed into
            a "m" secret key and "chain code".

        Parameters
        ----------
        words : List[str]
            Mnemonic words, usually 12 words.
        init_path : str, optional
            The initial derivation path, by default VET_EXTERNAL_PATH

        Returns
        -------
        HDNode
            A new HDNode.
        '''

        seed = derive_seed(words)  # 64 bytes
        bip32_ctx = Bip32.FromSeedAndPath(seed, init_path)
        return HDNode(bip32_ctx)

    @staticmethod
    def from_public_key(pub: bytes, chain_code: bytes):
        '''
        Construct an HD Node from an uncompressed public key.
        (starts with 0x04 as first byte)

        Parameters
        ----------
        pub : bytes
            An uncompressed public key in bytes.
        chain_code : bytes
            32 bytes

        Returns
        -------
        HDNode
            A new HDNode.
        '''
        # parts
        net_version = VERSION_MAINNET_PUBLIC
        depth = DEPTH_MASTER_NODE
        fprint = FINGER_PRINT_MASTER_KEY
        index = CHILD_NUMBER_MASTER_KEY
        chain = chain_code
        key_bytes = KeyAPI.PublicKey(strip_0x04(pub)).to_compressed_bytes()

        # assemble
        all_bytes = net_version + depth + fprint + index + chain + key_bytes
        # double sha-256 checksum
        xpub_str = Base58Encoder.CheckEncode(all_bytes)
        bip32_ctx = Bip32.FromExtendedKey(xpub_str)
        return HDNode(bip32_ctx)

    @staticmethod
    def from_private_key(priv: bytes, chain_code: bytes):
        '''
        Construct an HD Node from a private key.

        Parameters
        ----------
        priv : bytes
            The privte key in bytes.
        chain_code : bytes
            32 bytes of random number you choose.

        Returns
        -------
        HDNode
            A new HDNode.
        '''

        # print('input priv', len(priv))
        # parts
        net_version = VERSION_MAINNET_PRIVATE
        depth = DEPTH_MASTER_NODE
        fprint = FINGER_PRINT_MASTER_KEY
        index = CHILD_NUMBER_MASTER_KEY
        chain = chain_code
        key_bytes = b'\x00' + priv

        # assemble
        all_bytes = net_version + depth + fprint + index + chain + key_bytes
        # double sha-256 checksum
        xpriv = Base58Encoder.CheckEncode(all_bytes)
        bip32_ctx = Bip32.FromExtendedKey(xpriv)

        return HDNode(bip32_ctx)

    def derive(self, index: int):
        '''
        Derive the child HD Node from current HD Node.

        Note
        ----
            private key -> private key.
            private key -> public key.
            public key -> public key. 
            public key -> private key. (CAN NOT!)

        Parameters
        ----------
        index : int
            Which key index (0,1,2... 2^32-1) to derive.

        Returns
        -------
        HDNode
            A New HDNode.
        '''

        bip32_ctx = self.bip32_ctx.DerivePath(str(index))

        return HDNode(bip32_ctx)

    def public_key(self) -> bytes:
        '''
        Get current node's public key in uncompressed format bytes.
        (starts with 0x04)

        Returns
        -------
        bytes
            The uncompressed public key.
        '''
        return b'\x04' + self.bip32_ctx.PublicKey().RawUncompressed().ToBytes()

    def private_key(self) -> bytes:
        '''
        Get current node's private key in bytes format.
        If this node was publicly derived,
        then call this function may cause a Bip32KeyError exception.

        Returns
        -------
        bytes
            The private key in bytes.
        '''
        return self.bip32_ctx.PrivateKey().Raw().ToBytes()

    def chain_code(self) -> bytes:
        '''
        Get the chaincode of current HD node.

        Returns
        -------
        bytes
            32 bytes of chain code.
        '''
        return self.bip32_ctx.Chain()

    def address(self) -> bytes:
        '''
        Get the common address format.

        Returns
        -------
        bytes
            The address in bytes. (without prefix 0x)
        '''
        return public_key_to_address(self.public_key())

    def finger_print(self) -> bytes:
        '''
        Get the finger print of current HD Node public key.

        Returns
        -------
        bytes
            finger print in bytes.
        '''
        return self.bip32_ctx.FingerPrint()
