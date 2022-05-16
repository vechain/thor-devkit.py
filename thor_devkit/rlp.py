r"""RLP Encoding/Decoding layer for "real-world" objects."""
import sys
import warnings
from abc import ABC, abstractmethod
from itertools import dropwhile
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
)

from rlp import decode as rlp_decode
from rlp import encode as rlp_encode
from rlp.sedes import BigEndianInt
from voluptuous.error import Invalid

from thor_devkit import validation
from thor_devkit.cry.utils import izip
from thor_devkit.deprecation import deprecated, renamed_class
from thor_devkit.exceptions import DeserializationError, SerializationError

if sys.version_info < (3, 10):
    from typing_extensions import TypeGuard
else:
    from typing import TypeGuard


__all__ = [
    # Main
    "ComplexCodec",
    # Scalar
    "BytesKind",
    "NumericKind",
    "BlobKind",
    "FixedBlobKind",
    "OptionalFixedBlobKind",
    "CompactFixedBlobKind",
    # Wrappers
    "DictWrapper",
    "ListWrapper",
    "HomoListWrapper",
    # Abstract
    "AbstractSerializer",
    "ScalarKind",
    "BaseWrapper",
]

# We lack recursive types with mypy
_PackedSequenceT = Sequence[
    Union[bytes, Sequence[Union[bytes, Sequence[Union[bytes, Sequence[Any]]]]]]
]
_T = TypeVar("_T")


class AbstractSerializer(Generic[_T], ABC):
    """Abstract class for all serializers.

    .. versionadded:: 2.0.0
    """

    @abstractmethod
    def serialize(self, __obj: _T) -> Union[bytes, _PackedSequenceT]:
        """Serialize the object into a RLP encodable "item"."""
        raise NotImplementedError

    @abstractmethod
    def deserialize(self, __serial: Any) -> _T:
        """Deserialize given bytes into higher-level object."""
        raise NotImplementedError


class ScalarKind(AbstractSerializer[_T]):
    """Abstract class for all scalar serializers (they accept "basic" values)."""

    @abstractmethod
    def serialize(self, __obj: _T) -> bytes:
        """Serialize the object into a RLP encodable "item"."""
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
        """Serialize the object into a RLP encodable "item".

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
            If input is not bytes.
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
            If input is not bytes.
        """
        if not self.is_valid_type(serial):
            raise TypeError(
                f'Expected parameter of type "bytes", got: {type(serial)}', serial
            )

        return serial


class NumericKind(BigEndianInt, ScalarKind[int]):
    """Serializer for number-like objects.

    Good examples are::

        '0x0', '0x123', '0', '100', 0, 0x123, True

    Bad examples are::

        '0x123z', {}, '0x', -1, '0x12345678123456780'

    .. versionchanged:: 2.0.0
        Allowed :class:`bool` values :class:`True` and :class:`False`.
    """

    max_bytes: Optional[int]
    """Maximal allowed size of number, in bytes."""

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
        """Serialize the object into a RLP encodable "item".

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
            If input data is malformed
        TypeError
            If input is neither int nor string representation of int
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
        return bytes(dropwhile(lambda x: not x, result_bytes))

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
            serial = serial.rjust(self.max_bytes, b"\x00")
        return super().deserialize(serial)


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
            If input data is malformed.
        """
        try:
            return validation.hex_string(allow_prefix=True, to_bytes=True)(obj)
        except Invalid as e:
            raise SerializationError(str(e), obj)

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
            If input is not ``bytes`` nor ``bytearray``
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

    byte_length: int
    """Length of blob, in bytes."""

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
            If input data is malformed (e.g. wrong length)
        """
        try:
            validation.hex_string(self.byte_length * 2, allow_prefix=True)(obj)
        except Invalid as e:
            raise SerializationError(str(e), obj) from e

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
            If input is malformed (e.g. wrong length)
        """
        if len(serial) != self.byte_length:
            raise DeserializationError(
                f"Bytes should be of length {self.byte_length}", serial
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


@renamed_class("NoneableFixedBlobKind")
class NoneableFixedBlobKind(OptionalFixedBlobKind):
    """Deprecated alias for :class:`OptionalFixedBlobKind`.

    .. deprecated:: 2.0.0
        Use :class:`OptionalFixedBlobKind` instead.

    .. customtox-exclude::
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
        return bytes(dropwhile(lambda x: not x, b))

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
            If input is malformed.
        """
        if len(serial) > self.byte_length:
            raise DeserializationError(
                "Bytes too long, only need {}".format(self.byte_length), serial
            )

        if serial and not serial[0]:
            raise DeserializationError(
                "Byte sequence must have no leading zeroes", serial
            )

        padded = bytes(serial).rjust(self.byte_length, b"\x00")
        return super().deserialize(padded)


class BaseWrapper(AbstractSerializer[_T]):
    """Abstract serializer for complex types."""

    @abstractmethod
    def serialize(self, __obj: _T) -> _PackedSequenceT:
        """Serialize the object into a RLP encodable "item".

        .. versionadded:: 2.0.0
        """
        raise NotImplementedError

    @abstractmethod
    def deserialize(self, __serial: _PackedSequenceT) -> _T:
        """Deserialize given bytes into higher-level object.

        .. versionadded:: 2.0.0
        """
        raise NotImplementedError


class DictWrapper(BaseWrapper[Mapping[str, Any]]):
    """DictWrapper is a container for parsing dict like objects."""

    keys: Sequence[str]
    """Field names."""
    codecs: Sequence[AbstractSerializer[Any]]
    """Codecs to use for each field."""

    def __init__(
        self,
        codecs: Union[
            Sequence[Tuple[str, AbstractSerializer[Any]]],
            Mapping[str, AbstractSerializer[Any]],
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
            self.keys, self.codecs = izip(*codecs.items())
        else:
            self.keys, self.codecs = izip(*codecs)

    def __len__(self) -> int:
        """Count of serializable objects."""
        return len(self.codecs)

    def serialize(self, obj: Mapping[str, Any]) -> _PackedSequenceT:
        """Serialize dictionary to sequence of serialized values.

        .. versionadded:: 2.0.0

        Parameters
        ----------
        obj: Mapping[str, Any]
            Dictionary to serialize.

        Returns
        -------
        Sequence[bytes or Sequence[...]] (recursive)
            Sequence of serialized values.

        Raises
        ------
        SerializationError
            If input is malformed.
        """
        try:
            return [
                codec.serialize(obj[key])
                for (key, codec, _) in izip(self.keys, self.codecs, obj)
            ]
        except KeyError as e:
            raise SerializationError(f"Missing key: '{e.args[0]}'", obj)
        except ValueError as e:
            raise SerializationError(
                f"Keys count differs: expected {len(obj)}, got {len(self)}", obj
            ) from e

    def deserialize(self, serial: _PackedSequenceT) -> Dict[str, Any]:
        """Deserialize sequence of encoded values to dictionary with serialized values.

        .. versionadded:: 2.0.0

        Parameters
        ----------
        obj: Sequence[bytes or Sequence[...]] (recursive)
            Sequence of values to deserialize.

        Returns
        -------
        Mapping[str, Any]
            Deserialized values, mapping field names to decoded values.

        Raises
        ------
        DeserializationError
            If input is malformed.
        """
        try:
            return {
                key: codec.deserialize(blob)
                for (blob, key, codec) in izip(serial, self.keys, self.codecs)
            }
        except ValueError as e:
            raise DeserializationError(
                f"Keys count differs: expected {len(serial)}, got {len(self)}",
                serial,
            ) from e


class ListWrapper(BaseWrapper[Sequence[Any]]):
    """Container for parsing a heterogeneous list.

    The items in the list can be of different types.
    """

    codecs: Sequence[AbstractSerializer[Any]]
    """Codecs to use for each element of sequence."""

    def __init__(self, codecs: Sequence[AbstractSerializer[Any]]) -> None:
        """Create wrapper from items.

        Parameters
        ----------
        codecs : Sequence[AbstractSerializer]
            A list of codecs.
            eg. [codec, codec, codec...]
            codec is either a BaseWrapper, or a ScalarKind.
        """
        self.codecs = list(codecs)

    def __len__(self) -> int:
        """Count of serializable objects."""
        return len(self.codecs)

    def serialize(self, obj: Sequence[Any]) -> _PackedSequenceT:
        """Serialize sequence (list) of values to sequence of serialized values.

        .. versionadded:: 2.0.0

        Parameters
        ----------
        obj: Sequence[Any]
            Sequence of values to serialize.

        Returns
        -------
        Sequence[bytes or Sequence[...]] (recursive)
            Sequence of serialized values.

        Raises
        ------
        SerializationError
            If input is malformed.
        """
        try:
            return [codec.serialize(item) for (item, codec) in izip(obj, self.codecs)]
        except ValueError as e:
            raise SerializationError(
                f"Items count differs: expected {len(obj)}, got {len(self)}", obj
            ) from e

    def deserialize(self, serial: _PackedSequenceT) -> Sequence[Any]:
        """Deserialize sequence of encoded values to sequence.

        .. versionadded:: 2.0.0

        Parameters
        ----------
        obj: Sequence[bytes or Sequence[...]] (recursive)
            Sequence of values to deserialize.

        Returns
        -------
        Sequence[Any]
            Deserialized values.

        Raises
        ------
        DeserializationError
            If input is malformed.
        """
        try:
            return [
                codec.deserialize(blob) for (blob, codec) in izip(serial, self.codecs)
            ]
        except ValueError as e:
            raise DeserializationError(
                f"Items count differs: expected {len(serial)}, got {len(self)}",
                serial,
            ) from e


class HomoListWrapper(BaseWrapper[Sequence[Any]]):
    """Container for parsing a homogeneous list.

    Used when the items in the list are of the same type.
    """

    codec: AbstractSerializer[Any]
    """Codec to use for each element of array."""

    def __init__(self, codec: AbstractSerializer[Any]) -> None:
        """Create wrapper from items.

        Parameters
        ----------
        codec : AbstractSerializer
            codec is either a BaseWrapper, or a ScalarKind.
        """
        self.codec = codec

    def serialize(self, obj: Sequence[Any]) -> _PackedSequenceT:
        """Serialize sequence (list) of values to sequence of serialized values.

        .. versionadded:: 2.0.0

        Parameters
        ----------
        obj: Sequence[Any]
            Sequence of values to serialize.

        Returns
        -------
        Sequence[bytes or Sequence[...]] (recursive)
            Sequence of serialized values.

        Raises
        ------
        SerializationError
            If input is malformed.
        """
        return [self.codec.serialize(item) for item in obj]

    def deserialize(self, serial: _PackedSequenceT) -> Sequence[Any]:
        """Deserialize sequence of encoded values to sequence.

        .. versionadded:: 2.0.0

        Parameters
        ----------
        obj: Sequence[bytes or Sequence[...]] (recursive)
            Sequence of values to deserialize.

        Returns
        -------
        Sequence[Any]
            Deserialized values.

        Raises
        ------
        DeserializationError
            If input is malformed.
        """
        return [self.codec.deserialize(blob) for blob in serial]


@deprecated
def pack(obj: Any, wrapper: AbstractSerializer[Any]) -> Union[bytes, _PackedSequenceT]:
    """Pack a Python object according to wrapper.

    .. deprecated:: 2.0.0
        Use ``<wrapper>.serialize`` directly instead.

    .. customtox-exclude::

    Parameters
    ----------
    obj : Any
        A dict, a list, or a string/int/any...
    wrapper : AbstractSerializer[Any]
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
        If data cannot be serialized using specified codec.
    TypeError
        If wrapper type is unknown.
    """
    warnings.warn("Function 'pack' is deprecated. Use '<wrapper>.serialize' instead.")

    if not isinstance(wrapper, AbstractSerializer):
        raise TypeError(f"Wrapper type is unknown: {type(wrapper)}")

    return wrapper.serialize(obj)


@deprecated
def unpack(
    packed: Union[bytes, _PackedSequenceT],
    wrapper: AbstractSerializer[Any],
) -> Union[Dict[str, Any], List[Any], Any]:
    """Unpack a serialized thing back into a dict/list or a Python basic type.

    .. deprecated:: 2.0.0
        Use ``<wrapper>.deserialize`` directly instead.

    .. customtox-exclude::

    Parameters
    ----------
    packed : bytes or sequence of them
        A list of RLP encoded or pure bytes (may be nested).
    wrapper : AbstractSerializer[Any]
        The Wrapper.

    Returns
    -------
    Dict[str, Any] or List[Any] or Any
        dict/list if the wrapper instruction is dict/list,
        Python basic type if input is bytes.

    Raises
    ------
    DeserializationError
        If data cannot be deserialized using specified codec.
    TypeError
        If wrapper type is unknown.
    """
    warnings.warn(
        "Function 'unpack' is deprecated. Use '<wrapper>.deserialize' instead."
    )

    if not isinstance(wrapper, AbstractSerializer):
        raise TypeError("Wrapper type is unknown.")

    return wrapper.deserialize(packed)


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

    Abstract layer to join serialization and encoding
    (and reverse operations) together.
    """

    wrapper: AbstractSerializer[Any]
    """:class:`BaseWrapper` or :class:`ScalarKind` to use for serialization."""

    def __init__(self, wrapper: AbstractSerializer[Any]) -> None:
        self.wrapper = wrapper

    def encode(self, data: Any) -> bytes:
        """Serialize and RLP-encode given high-level data to bytes."""
        packed = self.wrapper.serialize(data)
        return rlp_encode(packed)

    def decode(self, data: bytes) -> Any:
        """RLP-decode and deserialize given bytes into higher-level structure."""
        to_be_unpacked = rlp_decode(data)
        return self.wrapper.deserialize(to_be_unpacked)
