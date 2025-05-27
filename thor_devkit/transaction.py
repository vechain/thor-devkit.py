'''
Transaction class defines VeChain's multi-clause transaction (tx).

This module defines data structure of a tx, and the encoding/decoding of tx data.
'''
from voluptuous import Schema, Any, Optional, REMOVE_EXTRA
from typing import Union, List
from copy import deepcopy
from enum import Enum, auto
from .rlp import NumericKind, CompactFixedBlobKind, NoneableFixedBlobKind, BlobKind, BytesKind
from .rlp import DictWrapper, HomoListWrapper
from .rlp import ComplexCodec
from .cry import blake2b256
from .cry import secp256k1
from .cry import address

class TransactionType(Enum):
    NORMAL = 0
    DYNAMIC_FEE = 81

# Kind Definitions
# Used for VeChain's "reserved features" kind.
FeaturesKind = NumericKind(4)

# Legacy Transactions
# Unsigned/Signed RLP Wrapper.
_legacy_params = [
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
    ("nonce", NumericKind(32)),
    ("reserved", HomoListWrapper(codec=BytesKind()))
]

# Unsigned Tx Wrapper
LegacyUnsignedTxWrapper = DictWrapper(_legacy_params)

# Signed Tx Wrapper
LegacySignedTxWrapper = DictWrapper( _legacy_params + [("signature", BytesKind())] )


# Dynamic Fee Transactions
# Unsigned/Signed RLP Wrapper.
_eip1559_params = [
    ("chainTag", NumericKind(1)),
    ("blockRef", CompactFixedBlobKind(8)),
    ("expiration", NumericKind(4)),
    ("clauses", HomoListWrapper(codec=DictWrapper([
        ("to", NoneableFixedBlobKind(20)),
        ("value", NumericKind(32)),
        ("data", BlobKind())
    ]))),
    ("maxPriorityFeePerGas", NumericKind(32)),
    ("maxFeePerGas", NumericKind(32)),
    ("gas", NumericKind(8)),
    ("dependsOn", NoneableFixedBlobKind(32)),
    ("nonce", NumericKind(32)),
    ("reserved", HomoListWrapper(codec=BytesKind()))
]

# Unsigned Tx Wrapper
EIP1559UnsignedTxWrapper = DictWrapper(_eip1559_params)

# Signed Tx Wrapper
EIP1559SignedTxWrapper = DictWrapper( _eip1559_params + [("signature", BytesKind())] )

CLAUSE = Schema(
    {
        "to": Any(str, None), # Destination contract address, or set to None to create contract.
        "value": Any(str, int), # VET to pass to the call.
        "data": str
    },
    required=True,
    extra=REMOVE_EXTRA
)

META = Schema(
    {
        "blockID": str,
        "blockNumber": int,
        "blockTimestamp": int
    },
    required=True,
    extra=REMOVE_EXTRA
)

RESERVED = Schema(
    {
        Optional("features"): int, # int.
        Optional("unused"): [bytes]
        # "unused" In TypeScript version is of type: Buffer[]
        # Buffer itself is "byte[]",
        # which is equivalent to "bytes"/"bytearray" in Python.
        # So Buffer[] is "[bytes]"/"[bytearray]" in Python.
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
        "gas": Any(str, int),
        "dependsOn": Any(str, None),
        Optional("size"): int,
        Optional("nonce"): str,
        Optional("meta"): META,
        Optional("delegator"): str,
        Optional("maxFeePerGas"): str,
        Optional("maxPriorityFeePerGas"): str,
        Optional("gasPriceCoef"): int,
        Optional("reserved"): RESERVED,
        Optional("type"): int
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

def right_trim_empty_bytes(m_list: List[bytes]) -> List:
    ''' Given a list of bytes, remove the b'' from the tail of the list.'''
    right_most_none_empty = None

    for i in range(len(m_list) - 1, -1, -1):
        if len(m_list[i]) != 0:
            right_most_none_empty = i
            break

    if right_most_none_empty is None:  # not found the right most none-empty string item
        return []

    return_list = m_list[:right_most_none_empty+1]

    return return_list


class Transaction():
    # The reserved feature of delegated (vip-191) is 1.
    DELEGATED_MASK = 1

    def __init__(self, body: dict):
        ''' Construct a transaction from a given body. '''
        self.body = BODY(body)
        self.signature = None
    
    def get_body(self, as_copy:bool = True):
        '''
        Get a dict of the body represents the transaction.
        If as_copy, return a newly created dict.
        If not, return the body used in this Transaction object.

        Parameters
        ----------
        as_copy : bool, optional
            Return a new dict clone of the body, by default True
        '''
        if as_copy:
            return deepcopy(self.body)
        else:
            return self.body

    def _encode_reserved(self) -> List:
        r = self.body.get('reserved', None)
        if not r:
            reserved = {"features": None, "unused": None}
        else:
            reserved = self.body['reserved']

        f = reserved.get('features') or 0
        l = reserved.get('unused') or []
        m_list = [FeaturesKind.serialize(f)] + l

        return_list = right_trim_empty_bytes(m_list)

        return return_list

    def get_signing_hash(self, delegate_for: str = None) -> bytes:
        reserved_list = self._encode_reserved()
        _temp = deepcopy(self.body)
        _temp.update({
            "reserved": reserved_list
        })
        
        if self.get_type() == TransactionType.DYNAMIC_FEE:
            buff = ComplexCodec(EIP1559UnsignedTxWrapper).encode(_temp)
        else:
            buff = ComplexCodec(LegacyUnsignedTxWrapper).encode(_temp)
            
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

    def get_gas_price_coef(self) -> Union[None, int]:
        ''' Get the gas of current transaction.'''
        return self.body.get('gasPriceCoef', 0)

    def get_max_fee_per_gas(self) -> Union[None, int]:
        ''' Get the max fee per gas of current transaction.'''
        value = self.body.get('maxFeePerGas', 0)
        if isinstance(value, str):
            return int(value, 16)
        return value

    def get_max_priority_fee_per_gas(self) -> Union[None, int]:
        ''' Get the max priority fee per gas of current transaction.'''
        value = self.body.get('maxPriorityFeePerGas', 0)
        if isinstance(value, str):
            return int(value, 16)
        return value

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
        temp = deepcopy(self.body)
        temp.update({
            'reserved': reserved_list
        })

        if self.signature:
            temp.update({
                'signature': self.signature
            })
            if self.get_type() == TransactionType.DYNAMIC_FEE:
                return ComplexCodec(EIP1559SignedTxWrapper).encode(temp)
            else:
                return ComplexCodec(LegacySignedTxWrapper).encode(temp)
        else:
            if self.get_type() == TransactionType.DYNAMIC_FEE:
                return ComplexCodec(EIP1559UnsignedTxWrapper).encode(temp)
            else:
                return ComplexCodec(LegacyUnsignedTxWrapper).encode(temp)

    @staticmethod
    def decode(raw: bytes, unsigned: bool):
        ''' Return a Transaction type instance '''
        body = None
        sig = None

        # First try to decode as dynamic fee transaction
        try:
            if unsigned:
                body = ComplexCodec(EIP1559UnsignedTxWrapper).decode(raw)
            else:
                decoded = ComplexCodec(EIP1559SignedTxWrapper).decode(raw)
                sig = decoded['signature']  # bytes
                del decoded['signature']
                body = decoded
            body['type'] = TransactionType.DYNAMIC_FEE.value
        except:
            # If that fails, try legacy transaction
            if unsigned:
                body = ComplexCodec(LegacyUnsignedTxWrapper).decode(raw)
            else:
                decoded = ComplexCodec(LegacySignedTxWrapper).decode(raw)
                sig = decoded['signature']  # bytes
                del decoded['signature']
                body = decoded
            body['type'] = TransactionType.NORMAL.value

        # Convert numeric values to hex strings
        if 'nonce' in body:
            body['nonce'] = hex(body['nonce'])
        if 'maxFeePerGas' in body:
            body['maxFeePerGas'] = hex(body['maxFeePerGas'])
        if 'maxPriorityFeePerGas' in body:
            body['maxPriorityFeePerGas'] = hex(body['maxPriorityFeePerGas'])

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
        flag_2 = self.encode() == other.encode() # only because of ["reserved"]["unused"] may glitch.
        return flag_1 and flag_2

    def get_type(self) -> TransactionType:
        ''' Get the type of the transaction.'''
        tx_type = self.body.get('type', 0)
        if tx_type == 81:
            return TransactionType.DYNAMIC_FEE
        return TransactionType.NORMAL