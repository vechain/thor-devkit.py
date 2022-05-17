"""Transaction class defines VeChain's multi-clause transaction (tx).

This module defines data structure of a transaction,
and the encoding/decoding of transaction data.
"""
import sys
import warnings
from copy import deepcopy
from typing import Any, Dict, List, Optional, Sequence, Union

import voluptuous
from voluptuous import REMOVE_EXTRA, Schema

from thor_devkit.cry import address, blake2b256, secp256k1
from thor_devkit.deprecation import deprecated, deprecated_to_property
from thor_devkit.exceptions import BadTransaction
from thor_devkit.rlp import (
    AbstractSerializer,
    BlobKind,
    BytesKind,
    CompactFixedBlobKind,
    ComplexCodec,
    DictWrapper,
    HomoListWrapper,
    NumericKind,
    OptionalFixedBlobKind,
)
from thor_devkit.validation import address_type, hex_integer

if sys.version_info < (3, 8):
    from typing_extensions import Final, TypedDict
else:
    from typing import Final, TypedDict
if sys.version_info < (3, 11):
    from typing_extensions import NotRequired
else:
    from typing import NotRequired


__all__ = [
    # Main
    "Transaction",
    # Types
    "ClauseT",
    "ReservedT",
    "TransactionBodyT",
    # Schemas
    "CLAUSE",
    "RESERVED",
    "BODY",
    # Other
    "UnsignedTxWrapper",
    "SignedTxWrapper",
    "data_gas",
    "intrinsic_gas",
]

FeaturesKind: Final = NumericKind(4)
"""Kind Definitions. Used for VeChain's "reserved features" kind."""

# Unsigned/signed RLP wrapper parameters.
_params: Final[Dict[str, AbstractSerializer[Any]]] = {
    "chainTag": NumericKind(1),
    "blockRef": CompactFixedBlobKind(8),
    "expiration": NumericKind(4),
    "clauses": HomoListWrapper(
        DictWrapper(
            {
                "to": OptionalFixedBlobKind(20),
                "value": NumericKind(32),
                "data": BlobKind(),
            }
        )
    ),
    "gasPriceCoef": NumericKind(1),
    "gas": NumericKind(8),
    "dependsOn": OptionalFixedBlobKind(32),
    "nonce": NumericKind(8),
    "reserved": HomoListWrapper(codec=BytesKind()),
}

UnsignedTxWrapper: Final = DictWrapper(_params)
"""Unsigned transaction wrapper.

:meta hide-value:
"""

SignedTxWrapper: Final = DictWrapper({**_params, "signature": BytesKind()})
"""Signed transaction wrapper.

:meta hide-value:
"""


class ClauseT(TypedDict):
    """Type of transaction clause.

    .. versionadded:: 2.0.0
    """

    to: Optional[str]
    """Transaction target contract, or ``None`` to create new one."""
    value: Union[str, int]
    """Amount to be paid (integer or its hex representation with ``0x``)."""
    data: str
    """VET to pass to the call."""


CLAUSE: Final = Schema(
    {
        # Destination contract address, or set to None to create contract.
        "to": voluptuous.Any(address_type(), None),
        "value": voluptuous.Any(hex_integer(to_int=True), int),  # VET to pass to call.
        "data": hex_integer(allow_empty=True),
    },
    required=True,
    extra=REMOVE_EXTRA,
)
"""
Validation :external:class:`~voluptuous.schema_builder.Schema` for transaction clause.

:meta hide-value:

.. versionchanged:: 2.0.0
    Added validation of ``to``, ``value`` and ``data`` as hex string.
"""


class ReservedT(TypedDict, total=False):
    """Type of ``reserved`` transaction field.

    .. versionadded:: 2.0.0
    """

    features: int
    """Integer (8 bit) with features bits set."""
    unused: Sequence[bytes]
    """Unused reserved fields."""


RESERVED: Final = Schema(
    {
        voluptuous.Optional("features"): int,  # int.
        voluptuous.Optional("unused"): [voluptuous.Any(bytes, bytearray)],
        # "unused" In TypeScript version is of type: Buffer[]
        # Buffer itself is "byte[]",
        # which is equivalent to "bytes"/"bytearray" in Python.
        # So Buffer[] is "[bytes]"/"[bytearray]" in Python.
    },
    required=True,
    extra=REMOVE_EXTRA,
)
"""
Validation :external:class:`~voluptuous.schema_builder.Schema`
for ``reserved`` transaction field.

:meta hide-value:
"""


class TransactionBodyT(TypedDict):
    """Type of transaction body.

    .. versionadded:: 2.0.0
    """

    chainTag: int  # noqa: N815
    """Last byte of genesis block ID"""
    blockRef: str  # noqa: N815
    """Block reference, ``0x...``-like hex string (8 bytes).

    First 4 bytes are block height, the rest is part of referred block ID.
    """
    expiration: int
    """Expiration (relative to blockRef, in blocks)"""
    clauses: Sequence[ClauseT]
    """Transaction clauses."""
    gasPriceCoef: int  # noqa: N815
    """Coefficient to calculate gas price."""
    gas: Union[int, str]
    """Maximum of gas to be consumed (int or its hex representation with ``0x``)."""
    dependsOn: Optional[str]  # noqa: N815
    """Address of transaction on which current transaction depends."""
    nonce: Union[int, str]
    """Transaction nonce (int or its hex representation with ``0x``)."""
    reserved: NotRequired[ReservedT]
    """Reserved field."""


BODY: Final = Schema(
    {
        "chainTag": int,
        "blockRef": hex_integer(16),
        "expiration": int,
        "clauses": [CLAUSE],
        "gasPriceCoef": int,
        "gas": voluptuous.Any(hex_integer(to_int=True), int),
        "dependsOn": voluptuous.Any(address_type(), None),
        "nonce": voluptuous.Any(hex_integer(to_int=True), int),
        voluptuous.Optional("reserved"): RESERVED,
    },
    required=True,
    extra=REMOVE_EXTRA,
)
"""
Validation :external:class:`~voluptuous.schema_builder.Schema`
for transaction body.

:meta hide-value:

.. versionchanged:: 2.0.0
    Added validation of ``gas``, ``dependsOn`` and ``nonce`` fields as hex string.
"""


def data_gas(data: str) -> int:
    """Calculate the gas the data will consume.

    Parameters
    ----------
    data : str
        ``0x...`` style hex string.

    Returns
    -------
    int
        Estimated gas consumption.
    """
    Z_GAS = 4
    NZ_GAS = 68

    return sum(
        Z_GAS if odd == even == "0" else NZ_GAS
        for odd, even in zip(data[2::2], data[3::2])
    )


def intrinsic_gas(clauses: Sequence[ClauseT]) -> int:
    """Calculate roughly the gas from a list of clauses.

    Parameters
    ----------
    clauses : Sequence[ClauseT]
        A list of clauses (in dict format).

    Returns
    -------
    int
        The amount of gas.
    """
    TX_GAS = 5000
    CLAUSE_GAS = 16000
    CLAUSE_CONTRACT_CREATION = 48000

    if not clauses:
        return TX_GAS + CLAUSE_GAS

    sum_total = TX_GAS
    for clause in clauses:
        if clause["to"]:  # Existing contract.
            sum_total += CLAUSE_GAS
        else:
            sum_total += CLAUSE_CONTRACT_CREATION
        sum_total += data_gas(clause["data"])

    return sum_total


def right_trim_empty_bytes(m_list: Sequence[bytes]) -> List[bytes]:
    """Given a list of bytes, remove the b'' from the tail of the list."""
    rightmost_none_empty = next(
        (idx for idx, item in enumerate(reversed(m_list)) if item), None
    )

    if rightmost_none_empty is None:
        return []

    return list(m_list[: len(m_list) - rightmost_none_empty])


class Transaction:
    """Multi-clause transaction.

    .. autoclasssumm:: Transaction
    """

    DELEGATED_MASK: Final = 1
    """Mask for delegation bit.

    The reserved feature of delegated (vip-191) is 1.
    """

    _signature: Optional[bytes] = None

    def __init__(self, body: TransactionBodyT) -> None:
        """Construct a transaction from a given body."""
        self._body: TransactionBodyT = BODY(body)

    @property
    def body(self) -> TransactionBodyT:
        """Get a dict of the body that represents the transaction."""
        return self._body

    def copy_body(self) -> TransactionBodyT:
        """Get a deep copy of transaction body."""
        return deepcopy(self.body)

    def _encode_reserved(self) -> List[bytes]:
        reserved = self.body.get("reserved", {})
        f = reserved.get("features") or 0
        unused: List[bytes] = list(reserved.get("unused", [])) or []
        m_list = [FeaturesKind.serialize(f)] + unused

        return right_trim_empty_bytes(m_list)

    def get_signing_hash(self, delegate_for: Optional[str] = None) -> bytes:
        """Get signing hash (with delegate address if given)."""
        buff = self.encode(force_unsigned=True)
        h, _ = blake2b256([buff])

        if delegate_for:
            if not address.is_address(delegate_for):
                raise ValueError("delegate_for should be an address type.")
            x, _ = blake2b256([h, bytes.fromhex(delegate_for[2:])])
            return x

        return h

    @property
    def intrinsic_gas(self) -> int:
        """Roughly estimate amount of gas this transaction will consume.

        .. versionadded:: 2.0.0
        """
        return intrinsic_gas(self.body["clauses"])

    @property
    def signature(self) -> Optional[bytes]:
        """Signature of transaction.

        .. versionadded:: 2.0.0
        """
        return self._signature

    @signature.setter
    def signature(self, sig: Optional[bytes]) -> None:
        """Set signature of transaction.

        .. versionadded:: 2.0.0
        """
        self._signature = bytes(sig) if sig is not None else sig

    @property
    def origin(self) -> Optional[str]:
        """Transaction origin.

        .. versionadded:: 2.0.0
        """
        if not self._signature_is_valid():
            return None

        sig = self.signature
        assert sig is not None

        try:
            my_sign_hash = self.get_signing_hash()
            pub_key = secp256k1.recover(my_sign_hash, sig[:65])
            return "0x" + address.public_key_to_address(pub_key).hex()
        except ValueError:
            return None

    @property
    def delegator(self) -> Optional[str]:
        """Transaction delegator.

        .. versionadded:: 2.0.0
        """
        if not self.is_delegated:
            return None

        if not self._signature_is_valid():
            return None

        sig = self.signature
        assert sig is not None

        origin = self.origin
        if not origin:
            return None

        try:
            my_sign_hash = self.get_signing_hash(origin)
            pub_key = secp256k1.recover(my_sign_hash, sig[65:])
            return "0x" + address.public_key_to_address(pub_key).hex()
        except ValueError:
            return None

    @property
    def is_delegated(self) -> bool:
        """Check if this transaction is delegated.

        .. versionchanged:: 2.0.0
            :attr:`is_delegated` is a property now.

        """
        if not self.body.get("reserved", {}).get("features"):
            return False

        return (
            self.body["reserved"]["features"] & self.DELEGATED_MASK
            == self.DELEGATED_MASK
        )

    @property
    def id(self) -> Optional[str]:  # noqa: A003
        """Transaction id.

        .. versionadded:: 2.0.0
        """
        if not self._signature_is_valid():
            return None

        sig = self.signature
        assert sig is not None

        try:
            my_sign_hash = self.get_signing_hash()
            pub_key = secp256k1.recover(my_sign_hash, sig[:65])
            origin = address.public_key_to_address(pub_key)
            return "0x" + blake2b256([my_sign_hash, origin])[0].hex()
        except ValueError:
            return None

    def _signature_is_valid(self) -> bool:
        if not self.signature:
            return False
        else:
            expected_sig_len = 65 * 2 if self.is_delegated else 65
            return len(self.signature) == expected_sig_len

    def encode(self, force_unsigned: bool = False) -> bytes:
        """Encode the tx into bytes."""
        reserved_list = self._encode_reserved()
        temp = dict(self.copy_body())  # cast to dict for mypy
        temp["reserved"] = reserved_list

        if not self.signature or force_unsigned:
            return ComplexCodec(UnsignedTxWrapper).encode(temp)
        else:
            temp["signature"] = self.signature
            return ComplexCodec(SignedTxWrapper).encode(temp)

    @staticmethod
    def decode(raw: bytes, unsigned: bool) -> "Transaction":
        """Create a Transaction type instance from encoded bytes."""
        sig = None

        if unsigned:
            body = ComplexCodec(UnsignedTxWrapper).decode(raw)
        else:
            body = ComplexCodec(SignedTxWrapper).decode(raw)
            sig = body.pop("signature")  # bytes

        r = body.pop("reserved", [])  # list of bytes
        if r:
            if not r[-1]:
                raise BadTransaction("invalid reserved fields: not trimmed.")

            reserved = {"features": FeaturesKind.deserialize(r[0])}
            if len(r) > 1:
                reserved["unused"] = r[1:]
            body["reserved"] = RESERVED(reserved)

        # Now body is a "dict", we try to check if it is in good shape.

        # Check if clause is in good shape.
        body["clauses"] = [CLAUSE(c) for c in body["clauses"]]

        tx = Transaction(body)

        if sig:
            tx.signature = sig

        return tx

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Transaction):
            return NotImplemented

        return (
            self.signature == other.signature
            # only because of ["reserved"]["unused"] may glitch.
            and self.encode() == other.encode()
        )

    @deprecated_to_property
    def get_delegator(self) -> Optional[str]:
        """Get delegator.

        .. customtox-exclude::

        .. deprecated:: 2.0.0
            Use :attr:`delegator` property instead.
        """
        return self.delegator

    @deprecated_to_property
    def get_intrinsic_gas(self) -> int:
        """Get intrinsic gas estimate.

        .. customtox-exclude::

        .. deprecated:: 2.0.0
            Use :attr:`intrinsic_gas` property instead.
        """
        return self.intrinsic_gas

    @deprecated_to_property
    def get_signature(self) -> Optional[bytes]:
        """Get signature.

        .. customtox-exclude::

        .. deprecated:: 2.0.0
            Use :attr:`signature` property instead.
        """
        return self.signature

    @deprecated_to_property
    def set_signature(self, sig: bytes) -> None:
        """Set signature.

        .. customtox-exclude::

        .. deprecated:: 2.0.0
            Use :attr:`signature` property setter instead.
        """
        self.signature = sig

    @deprecated_to_property
    def get_origin(self) -> Optional[str]:
        """Get origin.

        .. customtox-exclude::

        .. deprecated:: 2.0.0
            Use :attr:`origin` property instead.
        """
        return self.origin

    @deprecated_to_property
    def get_id(self) -> Optional[str]:
        """Get transaction ID.

        .. customtox-exclude::

        .. deprecated:: 2.0.0
            Use :attr:`.id` property instead.
        """
        return self.id

    @deprecated
    def get_body(self, as_copy: bool = True) -> TransactionBodyT:
        """Get a dict of the body that represents the transaction.

        .. deprecated:: 2.0.0
            Use :meth:`body` or :meth:`copy_body` instead.

        .. customtox-exclude::

        Parameters
        ----------
        as_copy : bool, default: True
            Return a new dict clone of the body

        Returns
        -------
        TransactionBodyT
            If as_copy, return a newly created dict.
            If not, return the body of this Transaction object.
        """
        warnings.warn(
            DeprecationWarning(
                "Method 'get_body' is deprecated."
                " Use 'body' property or 'copy_body' method instead."
            )
        )
        if as_copy:
            return self.copy_body()
        else:
            return self.body
