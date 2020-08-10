'''
Transaction class defines VeChain's multi-clause transaction (tx).

This module defines data structure of a tx, and the encoding/decoding of tx data.
'''
from voluptuous import Schema, Any, Optional, REMOVE_EXTRA
from typing import Union, List
from copy import deepcopy
from .rlp import NumericKind, CompactFixedBlobKind, NoneableFixedBlobKind, BlobKind, BytesKind
from .rlp import DictWrapper, HomoListWrapper
from .rlp import ComplexCodec
from .cry import blake2b256
from .cry import secp256k1
from .cry import address

# Kind Definitions
# Used for VeChain's "reserved features" kind.
FeaturesKind = NumericKind(4)

# Unsigned/Signed RLP Wrapper.
_params = [
    ("chainTag", NumericKind(1)),
    ("blockRef", CompactFixedBlobKind(8)),
    ("expiration", NumericKind(4)),
    ("clauses", HomoListWrapper(codec=DictWrapper([
        ("to", NoneableFixedBlobKind(20)),
        ("value", NumericKind(32)),
        ("data", BlobKind())
    ]))),
    ("gasPriceCoef", NumericKind(1)),
    ("gas", NumericKind(8)),
    ("dependsOn", NoneableFixedBlobKind(32)),
    ("nonce", NumericKind(8)),
    ("reserved", HomoListWrapper(codec=BytesKind()))
]

# Unsigned Tx Wrapper
UnsignedTxWrapper = DictWrapper(_params)

# Signed Tx Wrapper
SignedTxWrapper = DictWrapper( _params + [("signature", BytesKind())] )

CLAUSE = Schema(
    {
        "to": Any(str, None), # Destination contract address, or set to None to create contract.
        "value": Any(str, int), # VET to pass to the call.
        "data": str
    },
    required=True,
    extra=REMOVE_EXTRA
)


RESERVED = Schema(
    {
        Optional("features"): int, # int.
        Optional("unused"): [int] # list of int.
    },
    required=True,
    extra=REMOVE_EXTRA
)


BODY = Schema(
    {
        "chainTag": int,
        "blockRef": str,
        "expiration": int,
        "clauses": [CLAUSE],
        "gasPriceCoef": int,
        "gas": Any(str, int),
        "dependsOn": Any(str, None),
        "nonce": Any(str, int),
        Optional("reserved"): RESERVED
    },
    required=True,
    extra=REMOVE_EXTRA
)


def data_gas(data: str) -> int:
    '''
    Calculate the gas the data will consume.

    Parameters
    ----------
    data : str
        '0x...' style hex string.
    '''
    Z_GAS = 4
    NZ_GAS = 68

    sum_up = 0
    for x in range(2, len(data), 2):
        if data[x] == '0' and data[x+1] == '0':
            sum_up += Z_GAS
        else:
            sum_up += NZ_GAS

    # print('sum_up', sum_up)
    return sum_up


def intrinsic_gas(clauses: List) -> int:
    '''
    Calculate roughly the gas from a list of clauses.

    Parameters
    ----------
    clauses : List
        A list of clauses (in dict format).

    Returns
    -------
    int
        The sum of gas.
    '''
    TX_GAS = 5000
    CLAUSE_GAS = 16000
    CLAUSE_CONTRACT_CREATION = 48000

    if len(clauses) == 0:
        return TX_GAS + CLAUSE_GAS

    sum_total = 0
    sum_total += TX_GAS

    for clause in clauses:
        clause_sum = 0
        if clause['to']:  # contract create.
            clause_sum += CLAUSE_GAS
        else:
            clause_sum += CLAUSE_CONTRACT_CREATION
        clause_sum += data_gas(clause['data'])

        sum_total += clause_sum

    return sum_total


class Transaction():
    # The reserved feature of delegated (vip-191) is 1.
    DELEGATED_MASK = 1

    def __init__(self, body: dict):
        ''' Construct a transaction from a given body. '''
        self.body = BODY(body)
        self.signature = None

    def _encode_reserved(self) -> List:
        r = self.body.get('reserved', None)
        if not r:
            reserved = {"features": None, "unused": None}
        else:
            reserved = self.body['reserved']

        f = reserved.get('features') or 0
        l = reserved.get('unused') or []
        m_list = [FeaturesKind.serialize(f)] + l

        # While some elements in the m_list is b'' or '',
        # Then just right strip those '' from the list.
        length_list = [len(x) for x in m_list]

        right_most_none_empty = None
        for i in range(len(length_list) - 1, -1, -1):
            if length_list[i] != 0:
                right_most_none_empty = i
                break

        if right_most_none_empty is None:  # not found the right most none-empty string item
            return []

        return_list = []
        for y in range(0, right_most_none_empty + 1):
            return_list.append(m_list[y])

        return return_list

    def get_signing_hash(self, delegate_for: str = None) -> bytes:
        reserved_list = self._encode_reserved()
        _temp = deepcopy(self.body)
        _temp.update({"reserved": reserved_list})
        buff = ComplexCodec(UnsignedTxWrapper).encode(_temp)
        h, _ = blake2b256([buff])

        if delegate_for:
            if not address.is_address(delegate_for):
                raise Exception("delegate_for should be an address type.")
            x, _ = blake2b256([h, bytes.fromhex(delegate_for[2:])])
            return x

        return h

    def get_intrinsic_gas(self) -> int:
        ''' Get the rough gas this tx will consume'''
        return intrinsic_gas(self.body['clauses'])

    def get_signature(self) -> Union[None, bytes]:
        ''' Get the signature of current transaction.'''
        return self.signature

    def set_signature(self, sig: bytes):
        ''' Set the signature '''
        self.signature = sig

    def get_origin(self) -> Union[None, str]:
        if not self._signature_valid():
            return None

        try:
            my_sign_hash = self.get_signing_hash()
            pub_key = secp256k1.recover(
                my_sign_hash, self.get_signature()[0:65])
            return '0x' + address.public_key_to_address(pub_key).hex()
        except:
            return None

    def get_delegator(self) -> Union[None, str]:
        if not self.is_delegated():
            return None

        if not self._signature_valid():
            return None

        origin = self.get_origin()
        if not origin:
            return None

        try:
            my_sign_hash = self.get_signing_hash(origin)
            pub_key = secp256k1.recover(
                my_sign_hash, self.get_signature()[65:])
            return '0x' + address.public_key_to_address(pub_key).hex()
        except:
            return None

    def is_delegated(self):
        ''' Check if this transaction is delegated.'''
        if not self.body.get('reserved'):
            return False

        if not self.body.get('reserved').get('features'):
            return False

        return self.body['reserved']['features'] & self.DELEGATED_MASK == self.DELEGATED_MASK

    def _signature_valid(self) -> bool:
        if self.is_delegated():
            expected_sig_len = 65 * 2
        else:
            expected_sig_len = 65

        if not self.get_signature():
            return False
        else:
            return len(self.get_signature()) == expected_sig_len

    def get_id(self) -> Union[None, str]:
        if not self._signature_valid():
            return None
        try:
            my_sign_hash = self.get_signing_hash()
            pub_key = secp256k1.recover(
                my_sign_hash, self.get_signature()[0:65])
            origin = address.public_key_to_address(pub_key)
            return '0x' + blake2b256([my_sign_hash, origin])[0].hex()
        except:
            return None

    def encode(self):
        ''' Encode the tx into bytes '''
        reserved_list = self._encode_reserved()
        if self.signature:
            temp = deepcopy(self.body)
            temp.update({
                'reserved': reserved_list,
                'signature': self.signature
            })
            return ComplexCodec(SignedTxWrapper).encode(temp)
        else:
            temp = deepcopy(self.body)
            temp.update({
                'reserved': reserved_list
            })
            return ComplexCodec(UnsignedTxWrapper).encode(temp)

    @staticmethod
    def decode(raw: bytes, unsigned: bool):
        ''' Return a Transaction type instance '''
        body = None
        sig = None

        if unsigned:
            body = ComplexCodec(UnsignedTxWrapper).decode(raw)
        else:
            decoded = ComplexCodec(SignedTxWrapper).decode(raw)
            sig = decoded['signature']  # bytes
            del decoded['signature']
            body = decoded

        r = body.get('reserved', [])  # list of bytes
        if len(r) > 0:
            if len(r[-1]) == 0:
                raise Exception('invalid reserved fields: not trimmed.')

            features = FeaturesKind.deserialize(r[0])
            body['reserved'] = {
                'features': features
            }
            if len(r) > 1:
                body['reserved']['unused'] = r[1:]
        else:
            del body['reserved']

        # Now body is a "dict", we try to check if it is in good shape.

        # Check if clause is in good shape.
        _clauses = []
        for each in body['clauses']:
            _clauses.append( CLAUSE(each) )
        body['clauses'] = _clauses
        
        # Check if reserved is in good shape.
        _reserved = None
        if body.get('reserved'):
            _reserved = RESERVED(body['reserved'])
            body['reserved'] = _reserved

        tx = Transaction(body)

        if sig:
            tx.set_signature(sig)

        return tx

    def __eq__(self, other):
        ''' Compare two tx to be the same? '''
        flag_1 = (self.signature == other.signature)
        flag_2 = (self.body == other.body)
        return flag_1 and flag_2