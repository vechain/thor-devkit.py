r"""RLP Encoding/Decoding layer for "real-world" objects."""
import re
import sys
from abc import ABC, abstractmethod
from typing import (
    Any,
    Dict,
    Generic,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    overload,
)

from rlp import decode as rlp_decode
from rlp import encode as rlp_encode
from rlp.sedes import BigEndianInt

from thor_devkit.deprecation import class_renamed
from thor_devkit.exceptions import DeserializationError, SerializationError

if sys.version_info < (3, 8):
    from typing_extensions import Final
else:
    from typing import Final
if sys.version_info < (3, 10):
    from typing_extensions import TypeGuard
else:
    from typing import TypeGuard


__all__ = [
    "BytesKind",
    "NumericKind",
    "BlobKind",
    "FixedBlobKind",
    "OptionalFixedBlobKind",
    "CompactFixedBlobKind",
    "DictWrapper",
    "ListWrapper",
    "HomoListWrapper",
    "pack",
    "unpack",
    "ComplexCodec",
]

HEX_STRING_PATTERN: Final = re.compile("^0x[0-9a-f]*$", re.I)
NONEMPTY_HEX_STRING_PATTERN: Final = re.compile("^0x[0-9a-f]+$", re.I)


def _is_hex_string(a: str, must_contain_data: bool) -> bool:
    c = NONEMPTY_HEX_STRING_PATTERN if must_contain_data else HEX_STRING_PATTERN
    return bool(c.match(a))


_T = TypeVar("_T")


class ScalarKind(Generic[_T], ABC):
    """Abstract class for all serializers."""

    @abstractmethod
    def serialize(self, __obj: _T) -> bytes:
        """Serialize the object into a RLP encode-able "item"."""
        raise NotImplementedError

    @abstractmethod
    def deserialize(self, __serial: bytes) -> _T:
        """Deserialize given bytes into higher-level object."""
        raise NotImplementedError


class BytesKind(ScalarKind[bytes]):
    """Convert bytes type of Python object to RLP "item"."""

    @classmethod
    def is_valid_type(cls, obj: object) -> TypeGuard[bytes]:
        """Confirm that ``obj`` is :class:`bytes` or :class:`bytearray`."""
        return isinstance(obj, (bytes, bytearray))

    def serialize(self, obj: bytes) -> bytes:
        """Serialize the object into a RLP encode-able "item".

        Parameters
        ----------
        obj : bytes
            The input.

        Returns
        -------
        bytes
            The "item" in bytes.

        Raises
        ------
        TypeError
            raise if input is not bytes.
        """
        if not self.is_valid_type(obj):
            raise TypeError(
                f'Expected parameter of type "bytes", got: {type(obj)}', obj
            )

        return obj

    def deserialize(self, serial: bytes) -> bytes:
        """Deserialize a RLP "item" back to bytes.

        Parameters
        ----------
        serial : bytes
            The input.

        Returns
        -------
        bytes
            Original bytes.

        Raises
        ------
        TypeError
            raise if input is not bytes.
        """
        if not self.is_valid_type(serial):
            raise TypeError(
                f'Expected parameter of type "bytes", got: {type(serial)}', serial
            )

        return serial


class NumericKind(BigEndianInt, ScalarKind[int]):
    """Serializer for number-like objects.

    Good examples are::

        '0x0', '0x123', '0', '100', 0, 0x123

    Bad examples are::

        '0x123z', {}, '0x', -1, '0x12345678123456780', True

    .. versionchanged:: 2.0.0
        Allowed :class:`bool` values :class:`True` and :class:`False`.
    """

    def __init__(self, max_bytes: Optional[int] = None) -> None:
        """Initialize a NumericKind.

        Parameters
        ----------
        max_bytes : Optional[int], optional
            Max bytes in the encoded result (prepend 0 if there's not enough)
        """
        self.max_bytes = max_bytes
        super().__init__(l=max_bytes)

    def serialize(self, obj: Union[str, int]) -> bytes:
        """Serialize the object into a RLP encode-able "item".

        Parameters
        ----------
        obj : str or int
            obj is either int or string representation of int parseable by :func:`int`.

        Returns
        -------
        bytes
            Serialized data

        Raises
        ------
        SerializationError
            Input data is malformed
        TypeError
            Input is neither int nor string representation of int
        """
        if isinstance(obj, str):
            try:
                number = int(obj, 0)
            except ValueError:
                raise SerializationError(
                    "The input string does not represent a number.", obj
                )
        elif isinstance(obj, int):
            number = int(obj)
        else:
            raise TypeError(f"expected str or int, got: {type(obj)}")

        result_bytes = super().serialize(number)

        # remove leading 0 from bytes sequence.
        first_nonzero = next(
            (idx for idx, item in enumerate(result_bytes) if item), len(result_bytes)
        )
        return result_bytes[first_nonzero:]

    def deserialize(self, serial: bytes) -> int:
        """Deserialize bytes to int.

        Parameters
        ----------
        serial : bytes
            bytes

        Returns
        -------
        int
            Deserialized number.

        Raises
        ------
        DeserializationError
            If bytes contain leading 0.
        """
        if serial and not serial[0]:
            raise DeserializationError(
                "byte string must not have leading zeroes", serial
            )

        # add leading 0 to bytes sequence if width is set.
        if self.max_bytes:
            byte_list = list(serial)
            missed = self.max_bytes - len(byte_list)
            if missed:
                byte_list = [0] * missed + byte_list
            serial2 = bytes(byte_list)
        else:
            serial2 = serial
        return super().deserialize(serial2)


class BlobKind(ScalarKind[str]):
    """Serializer for ``0x....`` hex strings.

    Used for strings that shouldn't be interpreted as a number, usually an identifier.

    Examples: address, block_ref, data to smart contract.
    """

    def serialize(self, obj: str) -> bytes:
        """Serialize a ``0x...`` string to bytes.

        Parameters
        ----------
        obj : str
            ``0x...`` style string.

        Returns
        -------
        bytes
            Encoded string.

        Raises
        ------
        SerializationError
            Input data is malformed
        TypeError
            Input is not a string
        """
        if not isinstance(obj, str):
            raise TypeError(
                f'Serialized object must be of type "str", got: {type(obj)}'
            )

        if not _is_hex_string(obj, False):
            raise SerializationError("Expected 0x... style string", obj)

        if len(obj) % 2:
            raise SerializationError("Expected 0x... style string of even length.", obj)

        obj2 = obj[2:]  # remove '0x'

        return bytes.fromhex(obj2)

    def deserialize(self, serial: bytes) -> str:
        """Deserialize bytes to ``0x...`` string.

        Parameters
        ----------
        serial : bytes
            Encoded string.

        Returns
        -------
        str
            string of style ``0x...``

        Raises
        ------
        TypeError
            Input is not ``bytes`` nor ``bytearray``
        """
        if not isinstance(serial, (bytes, bytearray)):
            raise TypeError(f"expected bytes, got: {type(serial)}")

        return "0x" + serial.hex()


class FixedBlobKind(BlobKind):
    """Serializer for ``0x....`` **fixed-length** hex strings.

    Used for strings that shouldn't be interpreted as a number, usually an identifier.
    Examples: address, block_ref, data to smart contract.

    Note
    ----
        This kind has a fixed length of bytes.
        (also means the input hex is fixed length)
    """

    def __init__(self, byte_length: int) -> None:
        self.byte_length = byte_length

    def serialize(self, obj: str) -> bytes:
        """Serialize a ``0x...`` string to bytes.

        Parameters
        ----------
        obj : str
            ``0x...`` style string.

        Returns
        -------
        bytes
            Encoded string.

        Raises
        ------
        SerializationError
            Input data is malformed (e.g. wrong length)
        TypeError
            Input is not a string
        """
        # 0x counts for 2 chars. 1 bytes = 2 hex char.
        allowed_hex_length = self.byte_length * 2 + 2

        if not isinstance(obj, str):
            raise TypeError(
                f'serialized object must be of type "str", got: {type(obj)}'
            )

        if len(obj) != allowed_hex_length:
            raise SerializationError(
                f"Expected string of length {allowed_hex_length}", obj
            )

        return super().serialize(obj)

    def deserialize(self, serial: bytes) -> str:
        """Deserialize bytes to ``0x...`` string.

        Parameters
        ----------
        serial : bytes
            Encoded string.

        Returns
        -------
        str
            String of style ``0x...'``

        Raises
        ------
        DeserializationError
            Input is malformed (e.g. wrong length)
        """
        if len(serial) != self.byte_length:
            raise DeserializationError(
                "Bytes should be of length {}".format(self.byte_length), serial
            )

        return super().deserialize(serial)


class OptionalFixedBlobKind(FixedBlobKind):
    """Serializer for ``0x....`` fixed-length hex strings that may be :class:`None`.

    Used for strings that shouldn't be interpreted as a number, usually an identifier.
    Examples: address, block_ref, data to smart contract.

    Note
    ----
        This kind has a fixed length of bytes.
        (also means the input hex is fixed length)

        For this kind, input can be None.
        Then decoded is also None.
    """

    def __init__(self, byte_length: int) -> None:
        super().__init__(byte_length)

    def serialize(self, obj: Optional[str] = None) -> bytes:
        """Serialize a ``0x...`` string or :class:`None` to bytes.

        Parameters
        ----------
        obj : Optional[str], default: None
            ``0x...`` style string.

        Returns
        -------
        bytes
            Encoded string.
        """
        if obj is None:
            return bytes(0)

        return super().serialize(obj)

    # Unsafe override
    def deserialize(self, serial: bytes) -> Optional[str]:  # type: ignore[override]
        """Deserialize bytes to ``0x...`` string or :class:`None`.

        Parameters
        ----------
        serial : bytes
            Serialized data.

        Returns
        -------
        Optional[str]
            String of style ``0x...`` or :class:`None`
        """
        if not serial:
            return None

        return super().deserialize(serial)


@class_renamed("NoneableFixedBlobKind")
class NoneableFixedBlobKind(OptionalFixedBlobKind):
    """Deprecated alias for :class:`OptionalFixedBlobKind`.

    .. deprecated:: 2.0.0
        Use :class:`OptionalFixedBlobKind` instead.
    """


class CompactFixedBlobKind(FixedBlobKind):
    """Serializer for ``0x....`` fixed-length hex strings that may start with zeros.

    Used for strings that shouldn't be interpreted as a number, usually an identifier.
    Examples: address, block_ref, data to smart contract.

    Note
    ----
        When encode, the result fixed length bytes will be
        removed of leading zeros. i.e. ``000123 -> 123``

        When decode, it expects the input bytes length <= fixed_length.
        and it pads the leading zeros back. Output ``'0x{"0" * n}xxx...'``
    """

    def __init__(self, byte_length: int) -> None:
        super().__init__(byte_length)

    def serialize(self, obj: str) -> bytes:
        """Serialize a ``0x...`` string to bytes, stripping leading zeroes.

        Parameters
        ----------
        obj : str
            ``0x...`` style string.

        Returns
        -------
        bytes
            Encoded string with leading zeroes removed.
        """
        b = super().serialize(obj)
        first_non_zero_index = next(
            (idx for idx, each in enumerate(b) if each != 0), None
        )

        if first_non_zero_index is not None:
            b_list = b[first_non_zero_index:]
            return bytes(b_list) if b_list else bytes(0)

        return bytes(0)

    def deserialize(self, serial: bytes) -> str:
        """Deserialize bytes to ``0x...`` string.

        Parameters
        ----------
        serial : bytes
            Encoded data.

        Returns
        -------
        str
            String of style ``0x...`` of fixed length

        Raises
        ------
        DeserializationError
            Description
        """
        if len(serial) > self.byte_length:
            raise DeserializationError(
                "Bytes too long, only need {}".format(self.byte_length), serial
            )

        if serial and not serial[0]:
            raise DeserializationError(
                "Byte sequence must have no leading zeroes", serial
            )

        missing = self.byte_length - len(serial)
        b_list = [0] * missing + [x for x in serial]
        return super().deserialize(bytes(b_list))


class BaseWrapper:
    """BaseWrapper is a container for complex types to be encode/decoded."""


class DictWrapper(BaseWrapper):
    """DictWrapper is a container for parsing dict like objects."""

    def __init__(
        self,
        codecs: Union[
            Sequence[Tuple[str, Union[BaseWrapper, ScalarKind[Any]]]],
            Mapping[str, Union[BaseWrapper, ScalarKind[Any]]],
        ],
    ) -> None:
        """Create wrapper from items.

        Parameters
        ----------
        codecs : Mapping[str, BaseWrapper or ScalarKind] or its ``.values()``-like list
            Codecs to use.
            Possible values (codec is any BaseWrapper or ScalarKind):
            - Any mapping from str to codec, e.g. {'foo': NumericKind()}
            - Any sequence of tuples (name, codec), e.g. [('foo', NumericKind())]
        """
        if isinstance(codecs, Mapping):
            self.keys, self.codecs = zip(*codecs.items())
        else:
            self.keys, self.codecs = zip(*codecs)

    def __len__(self) -> int:
        """Count of serializable objects."""
        return len(self.codecs)


class ListWrapper(BaseWrapper):
    """Container for parsing a heterogeneous list.

    The items in the list can be of different types.
    """

    def __init__(self, codecs: Sequence[Union[BaseWrapper, ScalarKind[Any]]]) -> None:
        """Create wrapper from items.

        Parameters
        ----------
        codecs : Sequence[Union[BaseWrapper, ScalarKind[Any]]]
            A list of codecs.
            eg. [codec, codec, codec...]
            codec is either a BaseWrapper, or a ScalarKind.
        """
        self.codecs = list(codecs)

    def __len__(self) -> int:
        """Count of serializable objects."""
        return len(self.codecs)


class HomoListWrapper(BaseWrapper):
    """Container for parsing a homogeneous list.

    Used when the items in the list are of the same type.
    """

    def __init__(self, codec: Union[BaseWrapper, ScalarKind[Any]]) -> None:
        """Create wrapper from items.

        Parameters
        ----------
        codec : Union[BaseWrapper, ScalarKind[Any]]
            codec is either a BaseWrapper, or a ScalarKind.
        """
        self.codec = codec


# We lack recursive types with mypy
_PackedSequenceT = Sequence[
    Union[bytes, Sequence[Union[bytes, Sequence[Union[bytes, Sequence[Any]]]]]]
]
_PackedListT = List[Union[bytes, List[Union[bytes, List[Union[bytes, List[Any]]]]]]]


@overload
def pack(obj: _T, wrapper: ScalarKind[_T]) -> bytes:
    ...


@overload
def pack(obj: Any, wrapper: BaseWrapper) -> _PackedListT:
    ...


def pack(
    obj: Any, wrapper: Union[BaseWrapper, ScalarKind[Any]]
) -> Union[bytes, _PackedListT]:
    """Pack a Python object according to wrapper.

    Parameters
    ----------
    obj : Any
        A dict, a list, or a string/int/any...
    wrapper : Union[BaseWrapper, ScalarKind[Any]]
        A Wrapper.

    Returns
    -------
    bytes
        If obj is a basic type.
    List of packed items
        If obj is dict/list.

    Raises
    ------
    SerializationError
        Data cannot be serialized using specified codec.
    TypeError
        Unknown wrapper type.
    """
    # Simple wrapper: ScalarKind
    if isinstance(wrapper, ScalarKind):
        return wrapper.serialize(obj)

    # Complicated wrapper: BaseWrapper
    if isinstance(wrapper, BaseWrapper):
        # no zip(strict=True) before python 3.10, thus have to check manually
        if isinstance(wrapper, DictWrapper):
            if len(obj) != len(wrapper):
                raise SerializationError(
                    f"Keys count differs: expected {len(obj)}, got {len(wrapper)}", obj
                )
            try:
                return [
                    pack(obj[key], codec)
                    for (key, codec) in zip(wrapper.keys, wrapper.codecs)
                ]
            except KeyError as e:
                raise SerializationError(f"Missing key: {e.args[0]}", obj)

        if isinstance(wrapper, ListWrapper):
            if len(obj) != len(wrapper):
                raise SerializationError(
                    f"Items count differs: expected {len(obj)}, got {len(wrapper)}", obj
                )
            return [pack(item, codec) for (item, codec) in zip(obj, wrapper.codecs)]

        if isinstance(wrapper, HomoListWrapper):
            return [pack(item, wrapper.codec) for item in obj]

    raise TypeError("Wrapper type is unknown.{}".format(wrapper))


@overload
def unpack(packed: bytes, wrapper: ScalarKind[_T]) -> _T:
    ...


@overload
def unpack(packed: _PackedSequenceT, wrapper: DictWrapper) -> Dict[str, Any]:
    ...


@overload
def unpack(
    packed: _PackedSequenceT,
    wrapper: Union[ListWrapper, HomoListWrapper],
) -> List[Any]:
    ...


@overload
def unpack(
    packed: _PackedSequenceT, wrapper: BaseWrapper
) -> Union[Dict[str, Any], List[Any]]:
    ...


@overload
def unpack(
    packed: Union[bytes, _PackedSequenceT],
    wrapper: Union[BaseWrapper, ScalarKind[Any]],
) -> Union[Dict[str, Any], List[Any], Any]:
    ...


def unpack(
    packed: Union[bytes, _PackedSequenceT],
    wrapper: Union[BaseWrapper, ScalarKind[Any]],
) -> Union[Dict[str, Any], List[Any], Any]:
    """Unpack a serialized thing back into a dict/list or a Python basic type.

    Parameters
    ----------
    packed : bytes or sequence of them
        A list of RLP encoded or pure bytes (may be nested).
    wrapper : Union[BaseWrapper, ScalarKind[Any]]
        The Wrapper.

    Returns
    -------
    Dict[str, Any] or List[Any] or Any
        dict/list if the wrapper instruction is dict/list,
        Python basic type if input is bytes.

    Raises
    ------
    DeserializationError
        Data cannot be deserialized using specified codec.
    TypeError
        Unknown wrapper type.
    """
    # Simple wrapper: ScalarKind
    if isinstance(wrapper, ScalarKind):
        assert isinstance(packed, (bytes, bytearray))
        return wrapper.deserialize(packed)

    # Complicated wrapper: BaseWrapper
    if isinstance(wrapper, BaseWrapper):
        assert isinstance(packed, Iterable)
        assert not isinstance(packed, (bytes, bytearray))

        if isinstance(wrapper, DictWrapper):
            if len(packed) != len(wrapper):
                raise DeserializationError(
                    f"Keys count differs: expected {len(packed)}, got {len(wrapper)}",
                    packed,
                )

            return {
                key: unpack(blob, codec)
                for (blob, key, codec) in zip(packed, wrapper.keys, wrapper.codecs)
            }

        if isinstance(wrapper, ListWrapper):
            if len(packed) != len(wrapper):
                raise DeserializationError(
                    f"Items count differs: expected {len(packed)}, got {len(wrapper)}",
                    packed,
                )
            return [
                unpack(blob, codec) for (blob, codec) in zip(packed, wrapper.codecs)
            ]

        if isinstance(wrapper, HomoListWrapper):
            return [unpack(blob, wrapper.codec) for blob in packed]

    raise TypeError("Wrapper type is unknown.")


def pretty_print(
    packed: Union[bytes, _PackedSequenceT], indent: int = 0
) -> None:  # pragma: no cover
    """Pretty print the bytes into hex, indenting nested structures.

    Parameters
    ----------
    packed : bytes or sequence of them
        Data to print (may be nested).
    indent : int, default: 0
        Indent of topmost object, in spaces.

    Returns
    -------
    None
    """
    # indent of items
    internal_indent = 2

    # bytes? Direct print it.
    if isinstance(packed, (bytes, bytearray)):
        print(" " * (indent) + (packed.hex() or "(empty byte[])"))
        return

    # list?
    elif isinstance(packed, Iterable):
        # mypy isn't smart enough to deduce this from first `if`-branch
        assert not isinstance(packed, (bytes, bytearray))

        print(" " * (indent) + "[")
        for each in packed:
            pretty_print(each, indent + internal_indent)
        print(" " * (indent) + "]")


class ComplexCodec:
    """Wrapper around :class:`BaseWrapper` that implements RLP encoding.

    Provides access to module-level :func:`encode` and :func:`decode` functions
    as :meth:`encode` and :meth:`decode` methods
    """

    def __init__(self, wrapper: BaseWrapper) -> None:
        self.wrapper = wrapper

    def encode(self, data: Any) -> bytes:
        """RLP-encode given high-level data to bytes."""
        packed = pack(data, self.wrapper)
        return rlp_encode(packed)

    def decode(self, data: bytes) -> Any:
        """RLP-decode given bytes into higher-level structure."""
        to_be_unpacked = rlp_decode(data)
        return unpack(to_be_unpacked, self.wrapper)
