r"""ABI encoding module."""

import re
import sys
import warnings
from abc import ABC, abstractmethod
from collections import namedtuple
from keyword import iskeyword
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Generic,
    Iterable,
    Iterator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
    overload,
)

import eth_abi
import eth_utils
import voluptuous
from voluptuous import Schema

from thor_devkit.cry import keccak256
from thor_devkit.cry.utils import _with_doc_mro, izip
from thor_devkit.deprecation import deprecated_to_property

if sys.version_info < (3, 8):
    from typing_extensions import Final, Literal, TypedDict
else:
    from typing import Final, Literal, TypedDict
if sys.version_info < (3, 10):
    from typing_extensions import TypeAlias
else:
    from typing import TypeAlias
if sys.version_info < (3, 11):
    from typing_extensions import NotRequired
else:
    from typing import NotRequired

__all__ = [
    "Function",
    "Event",
    "Coder",
    "_ParameterT",
    "StateMutabilityT",
    "FuncParameterT",
    "FunctionT",
    "EventParameterT",
    "EventT",
    "MUTABILITY",
    "FUNC_PARAMETER",
    "FUNCTION",
    "EVENT_PARAMETER",
    "EVENT",
    "calc_event_topic",
    "calc_function_selector",
    "FunctionResult",
    "Encodable",
]

MUTABILITY: Final = Schema(voluptuous.Any("pure", "view", "payable", "nonpayable"))
"""
Validation :external:class:`~voluptuous.schema_builder.Schema`
for ``stateMutability`` parameter.

Must be a string, one of: "pure", "view", "payable", "nonpayable".

:meta hide-value:

.. versionchanged:: 2.0.0
    Removed unsupported "constant" option.
"""


StateMutabilityT: TypeAlias = Literal["pure", "view", "payable", "nonpayable"]
"""Literal type of ``stateMutability`` parameter.

Must be a string, one of: "pure", "view", "payable", "nonpayable".

.. versionadded:: 2.0.0
"""


class _ParameterT(TypedDict):
    """Base for parameter of function or event."""

    name: str
    """Parameter name."""
    type: str  # noqa: A003
    """Parameter type."""


FUNC_PARAMETER: Final = Schema(
    {
        "name": str,
        "type": str,
        voluptuous.Optional("internalType"): str,
        # if the "type" field is "tuple" or "type[]"
        voluptuous.Optional("components"): [voluptuous.Self],
    },
    required=True,
)
"""
Validation :external:class:`~voluptuous.schema_builder.Schema` for function parameter.

:meta hide-value:
"""


@_with_doc_mro(_ParameterT)
class FuncParameterT(_ParameterT):
    """Type of ABI function parameter.

    .. versionadded:: 2.0.0
    """

    internalType: NotRequired[str]  # noqa: N815
    """InternalType is used for struct name aliases, may be ignored."""
    # Recursive types aren't really supported, but do partially work
    # This will be expanded a few times and then replaced with Any (deeply nested)
    components: NotRequired[Sequence["FuncParameterT"]]  # type: ignore[misc]
    """Sequence of components, each must be :class:`FuncParameterT`."""


FUNCTION: Final = Schema(
    {
        "type": "function",
        "name": str,
        "stateMutability": MUTABILITY,
        "inputs": [FUNC_PARAMETER],
        "outputs": [FUNC_PARAMETER],
    },
    required=True,
    extra=voluptuous.REMOVE_EXTRA,
)
"""Validation :external:class:`~voluptuous.schema_builder.Schema` for ABI function.

:meta hide-value:

.. versionchanged:: 2.0.0
    Removed not required members which are not produced by solidity compiler
    by default, namely ``constant`` and ``payable``.
    All non-standard parameters are silently discarded now.
"""


class FunctionT(TypedDict):
    """Type of ABI function dictionary representation.

    .. versionadded:: 2.0.0
    """

    type: Literal["function"]  # noqa: A003
    """Always ``function``."""
    name: str
    """Function name."""
    stateMutability: StateMutabilityT  # noqa: N815
    r"""Mutability (pure, view, payable or nonpayable)."""
    inputs: Sequence["FuncParameterT"]
    """Function parameters."""
    outputs: Sequence["FuncParameterT"]
    """Function returns."""


EVENT_PARAMETER: Final = Schema(
    {
        "name": str,
        "type": str,
        voluptuous.Optional("components"): list,
        "indexed": bool,
        voluptuous.Optional("internalType"): str,  # since 0.5.11+
    },
    required=True,
)
"""Validation :external:class:`~voluptuous.schema_builder.Schema` for event parameter.

:meta hide-value:
"""


@_with_doc_mro(_ParameterT)
class EventParameterT(_ParameterT):
    """Type of ABI event parameter.

    .. versionadded:: 2.0.0
    """

    indexed: bool
    """Whether parameter is indexed."""
    internalType: NotRequired[str]  # noqa: N815
    """InternalType is used for struct name aliases, may be ignored."""
    # Recursive types aren't really supported, but do partially work
    # This will be expanded a few times and then replaced with Any (deeply nested)
    components: NotRequired[Sequence["EventParameterT"]]  # type: ignore[misc]
    """Sequence of components, each must be :class:`EventParameterT`."""


EVENT: Final = Schema(
    {
        "type": "event",
        "name": str,
        voluptuous.Optional("anonymous"): bool,
        "inputs": [EVENT_PARAMETER],
    }
)
"""Validation :external:class:`~voluptuous.schema_builder.Schema` for ABI event.

:meta hide-value:
"""


class EventT(TypedDict):
    """Type of ABI event dictionary representation.

    .. versionadded:: 2.0.0
    """

    type: Literal["event"]  # noqa: A003
    """Always ``event``."""
    name: str
    """Event name."""
    inputs: list["EventParameterT"]
    """Event inputs."""
    anonymous: NotRequired[bool]
    """Whether event is anonymous (does not include signature in ``topic``)."""


if TYPE_CHECKING:
    base = NamedTuple("base", [])
else:
    base = object


class FunctionResult(base):
    """Mixin for :class:`~typing.NamedTuple` with convenience methods.

    It is returned from :meth:`Event.decode` and :meth:`Function.decode`.

    When obtained from ``decode`` method of :class:`Function` or :class:`Event`,
    this class will contain decoded parameters. They can be obtained either by name
    or by numeric index as from plain tuples.

    .. versionadded:: 2.0.0

    Warning
    -------
    Names of result items can slightly differ from names in definition.
    See details below.

    See also
    --------
    :meth:`FunctionResult.name_to_identifier`: Details of names changing.

    :meth:`Function.decode`: for examples of items access
    """

    def to_dict(self) -> Dict[str, Any]:
        """Return dictionary representation (recursively).

        Returns
        -------
        Dict[str, Any]
            Dictionary of form ``{name: value}``
            (all inner namedtuples are converted too)

        Note
        ----
        This method reverts name changing, except empty strings.
        Unnamed parameters will be still represented as ``ret_{i}``,
        while python keywords are restored (so ``from_`` is again ``from`` key).
        """
        return {
            self.name_from_identifier(k): (
                v.to_dict()
                if isinstance(v, FunctionResult)
                else ([v_.to_dict() for v_ in v] if isinstance(v, list) else v)
            )
            for k, v in self._asdict().items()
        }

    def __getattr__(self, name: str) -> Any:
        """Dot attribute access (if not found).

        This is needed to make mypy happy with mix of this and dynamic namedtuple.
        We could use a mypy plugin to resolve names dynamically, but it is too
        difficult with small benefits. Now any attribute access is allowed,
        but all types are Any. If type-checking is very important, make sure to
        `assert` proper types to narrow them.
        """
        return super().__getattr__(name)  # type: ignore[misc]

    @staticmethod
    def name_to_identifier(word: str, position: int = 0) -> str:
        """Convert given word to valid python identifier.

        It assumes that ``word`` is a valid ``solidity`` identifier or empty string.

        The following rules apply:

        - Empty string are converted to ``f"ret_{position}"``
        - Python keyword (maybe already with underscores at the end)
          gets underscore (``_``) appended
        - All other words are returned unchanged.

        Parameters
        ----------
        word: str
            Solidity identifier to make compatible.
        position: int
            Arbitrary integer, unique for your collection
            (different for different calls).

        Returns
        -------
        str
            Valid python identifier.

        Raises
        ------
        ValueError
            If given string is not a valid solidity identifier.

        Examples
        --------
        >>> FunctionResult.name_to_identifier('foo')
        'foo'

        >>> FunctionResult.name_to_identifier('')
        'ret_0'

        >>> FunctionResult.name_to_identifier('', 1)
        'ret_1'

        >>> FunctionResult.name_to_identifier('for')
        'for_'

        >>> FunctionResult.name_to_identifier('from_')
        'from__'
        """
        if not word:
            return f"ret_{position}"

        if not word.isidentifier():
            raise ValueError(f"Invalid identifier given: {word}")

        if iskeyword(word.rstrip("_")):
            return f"{word}_"
        return word

    @staticmethod
    def name_from_identifier(word: str) -> str:
        r"""Reverse conversion to valid python identifier.

        It assumes that ``word`` was a result of
        :meth:`FunctionResult.name_to_identifier`.

        The following rules apply:

        - Word that are of form ``keyword(_)+`` (with at least one
          underscore ``_`` at the end) lose one underscore
        - All other words are returned unchanged.

        Parameters
        ----------
        word: str
            Identifier to reverse.

        Returns
        -------
        str
            Valid solidity identifier.

        Examples
        --------
        >>> FunctionResult.name_from_identifier('foo')
        'foo'

        >>> FunctionResult.name_from_identifier('ret_0')
        'ret_0'

        >>> FunctionResult.name_from_identifier('for_')
        'for'
        """
        if word.endswith("_") and iskeyword(word.rstrip("_")):
            return word[:-1]
        return word


def calc_function_selector(abi_json: FunctionT) -> bytes:
    """Calculate the function selector (4 bytes) from the ABI json."""
    f = FUNCTION(abi_json)
    return eth_utils.function_abi_to_4byte_selector(f)


def calc_event_topic(abi_json: EventT) -> bytes:
    """Calculate the event log topic (32 bytes) from the ABI json."""
    e = EVENT(abi_json)
    return eth_utils.event_abi_to_log_topic(e)


class Coder:
    """Convenient wrapper to namespace encoding functions."""

    @staticmethod
    def encode_list(types: Sequence[str], values: Sequence[Any]) -> bytes:
        """Encode a sequence of values, into a single bytes."""
        return eth_abi.encode_abi(types, values)

    @staticmethod
    def decode_list(types: Sequence[str], data: bytes) -> List[Any]:
        """Decode the data, back to a ``(...)`` tuple."""
        return list(eth_abi.decode_abi(types, data))

    @staticmethod
    def encode_single(t: str, value: Any) -> bytes:
        """Encode value of type ``t`` into single bytes."""
        return Coder.encode_list([t], [value])

    @staticmethod
    def decode_single(t: str, data: bytes) -> Any:
        """Decode data of type ``t`` back to a single object."""
        return Coder.decode_list([t], data)[0]


# The first should be right, but results in a crash.
# See https://github.com/python/mypy/issues/8320
# _ParamT = TypeVar("_ParamT", EventParameterT, FuncParameterT)
_ParamT = TypeVar("_ParamT", bound=_ParameterT)
_BaseT = TypeVar("_BaseT")
_T = TypeVar("_T")


class Encodable(Generic[_ParamT], ABC):
    """Base class for :class:`Function` and :class:`Event`.

    .. versionadded:: 2.0.0
    """

    _definition: FunctionT | EventT

    @property
    def name(self) -> str:
        """Get name of object."""
        return self._definition["name"]

    @deprecated_to_property
    def get_name(self) -> str:
        """Get name of object.

        .. customtox-exclude::

        .. deprecated:: 2.0.0
            Use :attr:`name` property instead.
        """
        return self.name

    @abstractmethod
    def encode(
        self, __parameters: Sequence[Any]
    ) -> Union[bytes, str, List[Optional[bytes]]]:
        """Encode parameters into bytes."""
        raise NotImplementedError()

    @abstractmethod
    def decode(self, __data: bytes) -> FunctionResult:
        """Decode data from bytes to namedtuple."""
        raise NotImplementedError()

    @classmethod
    def make_proper_type(cls, elem: _ParamT) -> str:
        """Extract type string (inline tuples) from JSON."""
        return eth_utils.abi.collapse_if_tuple(dict(elem))

    @staticmethod
    def _make_output_namedtuple_type(
        name: str, types: Iterable[_ParamT]
    ) -> Type[FunctionResult]:
        top_names = [
            FunctionResult.name_to_identifier(t["name"], i) for i, t in enumerate(types)
        ]
        return type(name, (namedtuple(name, top_names), FunctionResult), {})

    @classmethod
    def _demote_type(cls, typeinfo: _ParamT) -> Tuple[_ParamT, bool]:
        # We don't have to support nested stuff like (uint256, bool[4])[],
        # because type in JSON will be tuple[], uint256 and bool[4] in this case
        # without nesting in string
        type_ = typeinfo["type"]
        new_type_ = re.sub(r"(\[\d*\])$", r"", type_)
        if new_type_ == type_:
            return typeinfo.copy(), False

        new_type = typeinfo.copy()
        new_type["type"] = new_type_
        return new_type, True

    @classmethod
    def apply_recursive_names(
        cls,
        value: Any,
        typeinfo: _ParamT,
        chain: Optional[Sequence[str]] = None,
    ) -> Union[FunctionResult, List[FunctionResult], Any]:
        """Build namedtuple from values.

        .. customtox-exclude::
        """
        if not typeinfo["type"].startswith("tuple"):
            return value

        chain = [*(chain or []), typeinfo["name"].title() or "NoName"]

        new_type, demoted = cls._demote_type(typeinfo)
        if demoted:
            return [cls.apply_recursive_names(v, new_type, chain[:-1]) for v in value]

        components = cast(list[_ParamT], typeinfo.get("components", []))
        NewType = cls._make_output_namedtuple_type("_".join(chain), components)
        return NewType(
            *(
                cls.apply_recursive_names(v, t, chain)
                for t, v in izip(components, value)
            )
        )

    @classmethod
    def _normalize_values_dict(
        cls,
        values: Mapping[str, Any],
        expected: Union[_ParamT, Sequence[_ParamT]],
    ) -> Iterator[Any]:
        assert isinstance(values, Mapping)

        if isinstance(expected, Mapping):
            components = expected.get("components", [])
        else:
            components = expected
        if len(values) != len(components):
            raise ValueError(
                f"Invalid keys count, expected {len(components)}, got {len(values)}"
            )

        for typeinfo in components:
            name = typeinfo.get("name")
            if not name:
                raise ValueError(
                    "Cannot serialize mapping when some types are unnamed."
                )

            try:
                val = values[name]
            except KeyError:
                raise ValueError(f"Missing key for output: {name}.")

            yield cls._normalize_values(val, typeinfo)

    @overload
    @classmethod
    def _normalize_values(
        cls,
        values: Mapping[str, Any],
        expected: Union[_ParamT, Sequence[_ParamT]],
    ) -> Tuple[Any, ...]:
        ...

    @overload
    @classmethod
    def _normalize_values(
        cls,
        values: Sequence[Any],
        expected: Union[_ParamT, Sequence[_ParamT]],
    ) -> Sequence[Any]:
        ...

    @classmethod
    def _normalize_values(
        cls,
        values: object,
        expected: Union[_ParamT, Sequence[_ParamT]],
    ) -> object:
        if isinstance(values, Mapping):
            values = tuple(cls._normalize_values_dict(values, expected))

        if not (
            isinstance(values, Sequence)
            # Primary types
            and not isinstance(values, (str, bytes, bytearray))
        ):
            return values

        if isinstance(expected, Sequence):
            return tuple(cls._normalize_values(v, t) for v, t in izip(values, expected))
        type_ = expected["type"]
        new_type, demoted = cls._demote_type(expected)
        if demoted:
            return tuple(cls._normalize_values(v, new_type) for v in values)
        elif "tuple" in type_:
            components = cast(List[_ParamT], expected.get("components", []))
            assert components, "Missing components for tuple."
            return tuple(
                cls._normalize_values(v, t) for v, t in izip(values, components)
            )
        else:
            # Give up, maybe it is inline type like {'type': '(str,int)'}
            return tuple(values)

    @classmethod
    def _to_final_type(
        cls, name: str, values: Iterable[Any], types: Iterable[_ParamT]
    ) -> FunctionResult:
        NewType = cls._make_output_namedtuple_type(name, types)
        return NewType(
            *(
                cls.apply_recursive_names(value, typeinfo)
                for typeinfo, value in izip(types, values)
            )
        )


_dummy = object()


class Function(Encodable[FuncParameterT]):
    """ABI Function."""

    _definition: FunctionT

    def __init__(self, f_definition: FunctionT) -> None:
        """Initialize a function by definition.

        Parameters
        ----------
        f_definition : FunctionT
            A dict with style of :const:`FUNCTION`
        """
        self._definition = FUNCTION(f_definition)  # Protect.
        self._selector = calc_function_selector(f_definition)  # first 4 bytes.

    @property
    def selector(self) -> bytes:
        """First 4 bytes of function signature hash.

        .. versionadded:: 2.0.0
        """
        return self._selector

    @overload
    def encode(
        self, parameters: Union[Sequence[Any], Mapping[str, Any]], to_hex: Literal[True]
    ) -> str:
        ...

    @overload
    def encode(
        self,
        parameters: Union[Sequence[Any], Mapping[str, Any]],
        to_hex: Literal[False] = ...,
    ) -> bytes:
        ...

    def encode(
        self,
        parameters: Union[Sequence[Any], Mapping[str, Any]],
        to_hex: object = _dummy,
    ) -> Union[bytes, str]:
        r"""Encode the parameters according to the function definition.

        .. versionchanged:: 2.0.0
            parameter ``to_hex`` is deprecated, use ``"0x" + result.hex()``
            directly instead.

        Parameters
        ----------
        parameters : Sequence[Any] or Mapping[str, Any]
            A list of parameters waiting to be encoded,
            or a mapping from names to values.
        to_hex : bool, default: False
            If the return should be ``0x...`` hex string

        Returns
        -------
        bytes
            By default or if ``to_hex=False`` was passed.
        str
            If ``to_hex=True`` was passed.

        Examples
        --------
        Encode sequence:

        >>> func = Function({
        ...     'inputs': [{'internalType': 'string', 'name': '', 'type': 'string'}],
        ...     'outputs': [],
        ...     'name': 'myFunction',
        ...     'stateMutability': 'pure',
        ...     'type': 'function',
        ... })
        >>> enc = func.encode(['foo'])
        >>> assert enc == (
        ...     func.selector
        ...     + b'\x20'.rjust(32, b'\x00')  # Address of argument
        ...     + b'\x03'.rjust(32, b'\x00')  # Length
        ...     + b'foo'.ljust(32, b'\x00')  # String itself
        ... )

        Encode mapping:

        >>> func = Function({
        ...     'inputs': [{'internalType': 'string', 'name': 'arg', 'type': 'string'}],
        ...     'outputs': [],
        ...     'name': 'myFunction',
        ...     'stateMutability': 'pure',
        ...     'type': 'function',
        ... })
        >>> enc = func.encode({'arg': 'foo'})
        >>> assert enc == (
        ...     func.selector
        ...     + b'\x20'.rjust(32, b'\x00')  # Address of argument
        ...     + b'\x03'.rjust(32, b'\x00')  # Length
        ...     + b'foo'.ljust(32, b'\x00')  # String itself
        ... )
        """
        inputs = self._definition["inputs"]
        my_types = [self.make_proper_type(x) for x in inputs]

        norm_parameters = self._normalize_values(parameters, inputs)

        my_bytes = self.selector + Coder.encode_list(my_types, norm_parameters)
        if to_hex is not _dummy:
            warnings.warn(
                DeprecationWarning(
                    "to_hex parameter is deprecated. "
                    "Use ``'0x' + output.hex()`` instead to replicate that behaviour"
                )
            )
        if to_hex and to_hex is not _dummy:
            return "0x" + my_bytes.hex()
        else:
            return my_bytes

    def decode_parameters(self, value: bytes) -> FunctionResult:
        """Decode parameters back to values.

        .. versionadded:: 2.0.0

        Parameters
        ----------
        value: bytes
            Data to decode.

        Returns
        -------
        FunctionResult
            Decoded values.
        """
        my_types = [self.make_proper_type(x) for x in self._definition["inputs"]]
        # Strip signature
        result_list = Coder.decode_list(my_types, value[4:])

        return self._to_final_type("InType", result_list, self._definition["inputs"])

    def decode(self, output_data: bytes) -> FunctionResult:
        """Decode function call output data back into human readable results.

        The result is a dynamic subclass of
        :class:`typing.NamedTuple` (:func:`collections.namedtuple` return type)
        and :class:`FunctionResult`

        Parameters
        ----------
        output_data : bytes
            Data to decode.

        Returns
        -------
        FunctionResult
            Decoded data.

        Examples
        --------
        >>> data = {
        ...     "inputs": [],
        ...     "name": "getStr",
        ...     "outputs": [{"name": "memory", "type": "string"}],
        ...     "stateMutability": "pure",
        ...     "type": "function",
        ... }
        >>> func = Function(data)
        >>> memory = b"Hello world!"  # encoded string
        >>> binary = bytes.fromhex(
        ...     "20".rjust(64, "0")  # address of first argument
        ...     + hex(len(memory))[2:].rjust(64, "0")  # length of string
        ...     + memory.hex().ljust(64, "0")  # content
        ... )
        >>> result = func.decode(binary)
        >>> result.memory  # Access by name
        'Hello world!'

        >>> result[0]  # Access by index
        'Hello world!'

        >>> result.to_dict()  # Convert to dictionary
        {'memory': 'Hello world!'}

        With unnamed attributes:

        >>> data = {
        ...     "inputs": [],
        ...     "name": "getBool",
        ...     "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        ...     "stateMutability": "pure",
        ...     "type": "function",
        ... }
        >>> func = Function(data)
        >>> result = func.decode(bytes.fromhex("1".rjust(64, "0")))
        >>> result.ret_0  # Access by name
        True

        >>> result[0]  # Access by index
        True

        >>> result.to_dict()  # Convert to dictionary
        {'ret_0': True}
        """
        outputs = self._definition["outputs"]
        my_types = [self.make_proper_type(x) for x in outputs]
        result_list = Coder.decode_list(my_types, output_data)

        return self._to_final_type("OutType", result_list, self._definition["outputs"])

    def encode_outputs(self, values: Union[Sequence[Any], Mapping[str, Any]]) -> bytes:
        """Encode the return values according to the function definition.

        .. versionadded:: 2.0.0

        Parameters
        ----------
        values : Sequence[Any] or Mapping[str, Any]
            A list of parameters waiting to be encoded,
            or a mapping from names to values.

        Returns
        -------
        bytes
            Encoded output values.

        Raises
        ------
        ValueError
            If mapping was given for unnamed parameters
            or mapping keys are not the same as output names.
        """
        outputs = self._definition["outputs"]
        my_types = [self.make_proper_type(x) for x in outputs]

        return Coder.encode_list(my_types, self._normalize_values(values, outputs))

    @deprecated_to_property
    def get_selector(self) -> bytes:
        """First 4 bytes of function signature hash.

        .. customtox-exclude::

        .. deprecated:: 2.0.0
            Use :attr:`selector` property instead.
        """
        return self.selector


class Event(Encodable[EventParameterT]):
    """ABI Event."""

    _definition: EventT

    def __init__(self, e_definition: EventT) -> None:
        """Initialize an Event with definition.

        Parameters
        ----------
        e_definition : EventT
            A dict with style of :const:`EVENT`.

        Raises
        ------
        ValueError
            Number of indexed parameters exceeds the limit.
        """
        self._definition = EVENT(e_definition)
        self._signature = calc_event_topic(self._definition)

        self.indexed_params = [x for x in self._definition["inputs"] if x["indexed"]]

        if len(self.indexed_params) - int(self.is_anonymous) > 3:
            raise ValueError("Too much indexed parameters!")

        self.unindexed_params = [
            x for x in self._definition["inputs"] if not x["indexed"]
        ]

    @property
    def is_anonymous(self) -> bool:
        """Whether this event is anonymous.

        .. versionadded:: 2.0.0
        """
        return self._definition.get("anonymous", False)

    @property
    def signature(self) -> bytes:
        """First 4 bytes of event signature hash.

        .. versionadded:: 2.0.0
        """
        return self._signature

    @classmethod
    def is_dynamic_type(cls, t: str) -> bool:
        """Check if the input type requires hashing in indexed parameter.

        All bytes, strings and dynamic arrays are dynamic, plus all structs and
        fixed-size arrays are hashed (see `Specification`_).
        """  # Reference is defined in `abi.rst`
        return t in {"bytes", "string"} or "[" in t or t.startswith("tuple")

    @staticmethod
    def _strip_dynamic_part(type_: str) -> str:
        return type_.split("[")[0]

    @staticmethod
    def _pad(
        data: Union[Sequence[bytes], bytes],
        mod: int,
        to: Literal["r", "l"] = "l",
    ) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            data = b"".join(data)

        length = len(data)
        missing = (mod * (length // mod + 1) - length) % mod
        if to == "l":
            return bytes(data) + missing * b"\x00"
        else:
            return missing * b"\x00" + bytes(data)

    @classmethod
    def dynamic_type_to_topic(cls, type_: EventParameterT, value: Any) -> List[bytes]:
        """Encode single value according to given ``type_``."""
        t_type = type_["type"]
        new_type, demoted = cls._demote_type(type_)
        if demoted:
            return [
                cls._pad(cls.dynamic_type_to_topic(new_type, v), 32, "l") for v in value
            ]

        if t_type.startswith("tuple"):
            return [
                cls._pad(cls.dynamic_type_to_topic(t, v), 32, "l")
                for t, v in izip(type_["components"], value)
            ]

        if t_type == "string":
            assert isinstance(value, str), 'Value of type "string" must be str'
            return [value.encode("utf-8")]
        elif t_type == "bytes":
            assert isinstance(
                value, (bytes, bytearray)
            ), 'Value of type "bytes" must be bytes'
            return [value]
        else:
            return [Coder.encode_single(cls._strip_dynamic_part(t_type), value)]

    def encode(
        self, parameters: Union[Mapping[str, Any], Sequence[Any]]
    ) -> List[Optional[bytes]]:
        r"""Assemble indexed keys into topics.

        Commonly used to filter out logs of concerned topics, e.g. to filter out
        `VIP180 <https://github.com/vechain/VIPs/blob/master/vips/VIP-180.md>`_
        transfer logs of a certain wallet, certain amount.

        Parameters
        ----------
        parameters : Mapping[str, Any] or Sequence[Any]
            A dict/list of indexed parameters of the given event.
            Fill in :class:`None` to occupy the position, if you aren't sure
            about the value.

        Returns
        -------
        List[bytes or None]
            Encoded parameters with :class:`None` preserved from input.

        Raises
        ------
        TypeError
            Unknown parameters type (neither mapping nor sequence)
        ValueError
            If there is unnamed parameter in definition and dict of parameters is given,
            or if parameters count doesn't match the definition.

        Examples
        --------
        Let's say we have

        .. code-block:: text

            MyEvent(address from indexed, address to indexed, uint256 value)

        Then corresponding event is

        >>> event = Event({
        ...     'inputs': [
        ...         {'name': 'from', 'indexed': True, 'type': 'address'},
        ...         {'name': 'to', 'indexed': True, 'type': 'address'},
        ...         {'name': 'value', 'indexed': False, 'type': 'uint256'},
        ...     ],
        ...     'name': 'MyEvent',
        ...     'type': 'event',
        ... })

        We can use it to encode all topics:

        >>> address_from = '0x' + 'f' * 40
        >>> address_to = '0x' + '9' * 40
        >>> enc = event.encode([address_from, address_to])
        >>> assert tuple(enc) == (
        ...     event.signature,
        ...     bytes.fromhex(hex(int(address_from, 16))[2:].rjust(64, '0')),
        ...     bytes.fromhex(hex(int(address_to, 16))[2:].rjust(64, '0')),
        ... )

        Note the interesting conversion here: ``address`` is equivalent to ``uint160``,
        so one would expect just ``bytes.fromhex(address_from[2:])``, right?
        Indexed event parameters are **always** padded to 32 bytes too, even if they
        are shorter. Numbers are padded to the right (or as two's complement,
        if negative), strings and bytes - to the left.

        Or we can convert only some of params:

        >>> enc = event.encode([address_from, None])
        >>> assert tuple(enc) == (
        ...     event.signature,
        ...     bytes.fromhex(hex(int(address_from, 16))[2:].rjust(64, '0')),
        ...     None,
        ... )

        Mapping is also accepted for named parameters:

        >>> enc = event.encode({'from': address_from, 'to': None})
        >>> assert tuple(enc) == (
        ...     event.signature,
        ...     bytes.fromhex(hex(int(address_from, 16))[2:].rjust(64, '0')),
        ...     None,
        ... )

        """
        topics: List[Optional[bytes]] = []

        parameters = self._normalize_values(parameters, self.indexed_params)

        # not anonymous? topic[0] = signature.
        if not self.is_anonymous:
            topics.append(self.signature)

        def encode(param: Any, definition: EventParameterT) -> bytes:
            if self.is_dynamic_type(definition["type"]):
                return keccak256(self.dynamic_type_to_topic(definition, param))[0]
            else:
                return Coder.encode_single(self.make_proper_type(definition), param)

        if (
            isinstance(parameters, Sequence)
            and not isinstance(parameters, (bytes, bytearray))
            # bytes are Sequence too!
        ):
            for param, definition in izip(parameters, self.indexed_params):
                topics.append(param if param is None else encode(param, definition))
        else:
            raise TypeError(
                f"Expected sequence or mapping of parameters, got: {type(parameters)}"
            )

        return list(topics)

    def encode_data(self, parameters: Union[Mapping[str, Any], Sequence[Any]]) -> bytes:
        """Encode unindexed parameters into bytes.

        .. versionadded:: 2.0.0

        Parameters
        ----------
        parameters: Mapping[str, Any] or Sequence[Any]
            A dict/list of unindexed parameters of the given event.

        Returns
        -------
        bytes
            Encoded result.

        Examples
        --------
        >>> event = Event({
        ...     'inputs': [
        ...         {'name': 'from', 'indexed': True, 'type': 'address'},
        ...         {'name': 'value', 'indexed': False, 'type': 'uint256'},
        ...         {'name': 'to', 'indexed': True, 'type': 'address'},
        ...         {'name': 'value2', 'indexed': False, 'type': 'uint64'},
        ...     ],
        ...     'name': 'MyEvent',
        ...     'type': 'event',
        ... })

        We can use it to encode values as a sequence:

        >>> enc = event.encode_data([256, 129])  # 256 == 0x100, 129 == 0x81
        >>> assert enc.hex() == '100'.rjust(64, '0') + '81'.rjust(64, '0')

        Or as a mapping:

        >>> enc = event.encode_data({'value': 256, 'value2': 129})
        >>> assert enc.hex() == '100'.rjust(64, '0') + '81'.rjust(64, '0')
        """
        parameters = self._normalize_values(parameters, self.unindexed_params)
        my_types = list(map(self.make_proper_type, self.unindexed_params))
        return Coder.encode_list(my_types, parameters)

    def encode_full(
        self, parameters: Union[Mapping[str, Any], Sequence[Any]]
    ) -> Tuple[List[Optional[bytes]], bytes]:
        r"""Encode both indexed and unindexed parameters.

        .. versionadded:: 2.0.0

        Parameters
        ----------
        parameters: Mapping[str, Any] or Sequence[Any]
            A dict/list of all parameters of the given event.

        Returns
        -------
        Tuple[List[bytes or None], bytes]
            Tuple
            with first item being :meth:`Event.encode` result
            and second item being :meth:`Event.encode_data` result.

        Raises
        ------
        KeyError
            If some required parameters were missing.
        ValueError
            If some extra parameters were given.

        Examples
        --------
        >>> event = Event({
        ...     'inputs': [
        ...         {'name': 'from', 'indexed': True, 'type': 'address'},
        ...         {'name': 'value', 'indexed': False, 'type': 'uint256'},
        ...         {'name': 'to', 'indexed': True, 'type': 'address'},
        ...         {'name': 'value2', 'indexed': False, 'type': 'uint64'},
        ...     ],
        ...     'name': 'MyEvent',
        ...     'type': 'event',
        ... })
        >>> address_from = '0x' + 'f' * 40
        >>> address_to = '0x' + '9' * 40

        Expected values:

        >>> topics_enc = event.encode([address_from, address_to])
        >>> data_enc = event.encode_data([256, 127])

        Now with :meth:`Event.encode_full`:

        >>> topics, data = event.encode_full([address_from, 256, address_to, 127])
        >>> assert topics == topics_enc
        >>> assert data == data_enc

        Or in mapping form (note that order doesn't matter):

        >>> topics, data = event.encode_full({
        ...     'to': address_to,
        ...     'value': 256,
        ...     'value2': 127,
        ...     'from': address_from,
        ... })
        >>> assert topics == topics_enc
        >>> assert data == data_enc

        """
        unindexed: Union[List[Any], Dict[str, Any]]
        indexed: Union[List[Any], Dict[str, Any]]

        if isinstance(parameters, Mapping):
            unindexed = {
                p["name"]: parameters[p["name"]] for p in self.unindexed_params
            }
            indexed = {p["name"]: parameters[p["name"]] for p in self.indexed_params}
            if len(indexed) + len(unindexed) != len(parameters):
                raise ValueError("Invalid keys count.")
        elif isinstance(parameters, Sequence):
            unindexed = [
                v
                for v, p in izip(parameters, self._definition["inputs"])
                if not p["indexed"]
            ]
            indexed = [
                v
                for v, p in izip(parameters, self._definition["inputs"])
                if p["indexed"]
            ]
        else:
            raise TypeError("Sequence or mapping of parameters expected.")

        return (self.encode(indexed), self.encode_data(unindexed))

    def decode(
        self,
        data: bytes,
        topics: Optional[Sequence[Optional[bytes]]] = None,
        strict: bool = True,
    ) -> FunctionResult:
        r"""Decode "data" according to the "topic"s.

        One output can contain an array of logs.

        Parameters
        ----------
        data : bytes
            Data to decode.
            It should be ``b'\x00'`` for event without unindexed parameters.
        topics : Sequence[bytes or None], optional
            Sequence of topics.
            Fill unknown or not important positions with :class:`None`,
            it will be preserved.

            :class:`None` is interpreted like empty list.
        strict : bool, default: True
            Raise an exception if topics count is less than expected.
            If ``False``, topics will be padded with :class:`None` (to the left).

        Returns
        -------
        FunctionResult
            Decoded data.

        Raises
        ------
        ValueError
            If topics count does not match the number of indexed parameters.

        Note
        ----
        One log contains mainly 3 entries:

        - For a non-indexed parameters event::

            "address": "The emitting contract address",
            "topics": [
                "signature of event"
            ],
            "data": "0x..."  # contains parameters values

        - For an indexed parameters event::

            "address": "The emitting contract address",
            "topics": [
                "signature of event",
                "indexed param 1",
                "indexed param 2",
                # ...
                # --> max 3 entries of indexed params.
            ],
            "data": "0x..."  # remaining unindexed parameters values

        If the event is "anonymous" then the signature is not inserted into
        the "topics" list, hence ``topics[0]`` is not the signature.

        Examples
        --------
        Decode indexed topic that is not hashed:

        >>> event = Event({
        ...     'inputs': [
        ...         {'indexed': True, 'name': 'a1', 'type': 'bool'},
        ...     ],
        ...     'name': 'MyEvent',
        ...     'type': 'event',
        ... })
        >>> topics = [
        ...     event.signature,  # Not anonymous
        ...     b'\x01'.rjust(32, b'\x00'),  # True as 32-byte integer
        ... ]
        >>> data = b'\x00'  # No unindexed topics
        >>> event.decode(data, topics).to_dict()
        {'a1': True}

        Decode mix of indexed and unindexed parameters:

        >>> event = Event({
        ...     'inputs': [
        ...         {'indexed': True, 'name': 't1', 'type': 'bool'},
        ...         {'indexed': True, 'name': 't2', 'type': 'bool'},
        ...         {'indexed': False, 'name': 'u1', 'type': 'string'},
        ...     ],
        ...     'name': 'MyEvent',
        ...     'type': 'event',
        ...     'anonymous': True,
        ... })
        >>> topics = [
        ...     b'\x01'.rjust(32, b'\x00'),  # True as 32-byte integer
        ...     b'\x00'.rjust(32, b'\x00'),  # False as 32-byte integer
        ... ]
        >>> data = (
        ...     b''
        ...     + b'\x20'.rjust(32, b'\x00')  # address of first argument
        ...     + b'\x03'.rjust(32, b'\x00')  # length of b'foo'
        ...     + b'foo'.ljust(32, b'\x00')  # b'foo'
        ... )  # string 'foo' encoded
        >>> event.decode(data, topics).to_dict()
        {'t1': True, 't2': False, 'u1': 'foo'}

        "Decode" hashed topic:

        >>> from thor_devkit.cry import keccak256
        >>> event = Event({
        ...     'inputs': [
        ...         {'indexed': True, 'name': 't1', 'type': 'string'},
        ...     ],
        ...     'name': 'MyEvent',
        ...     'type': 'event',
        ...     'anonymous': True,
        ... })
        >>> encoded_topic = b'foo'.ljust(32, b'\x00')
        >>> topic = keccak256([encoded_topic])[0]
        >>> assert event.decode(b'\x00', [topic]).t1 == topic

        Note that we don't get a string as output due to the nature of
        indexed parameters.

        See also
        --------
        :meth:`Function.decode`: for examples of result usage.
        """
        if not self.is_anonymous and topics:
            # if not anonymous, topics[0] is the signature of event.
            # we cut it out, because we already have self.signature
            sig, *topics = topics
            if sig != self.signature:
                raise ValueError(
                    "First topic of non-anonymous event must be its signature"
                )

        indexed_count, topics_count = len(self.indexed_params), len(topics or [])
        if topics is not None and indexed_count != topics_count:
            if not strict and indexed_count > topics_count:
                topics = list(topics or []) + [None] * (indexed_count - topics_count)
            else:
                raise ValueError("Invalid topics count.")
        topics = topics or []

        my_types = list(map(self.make_proper_type, self.unindexed_params))
        result_list = Coder.decode_list(my_types, data)
        unindexed_params = (
            self.apply_recursive_names(value, typeinfo)
            for typeinfo, value in izip(self.unindexed_params, result_list)
        )

        inputs = self._definition["inputs"]
        topics = iter(topics)
        r: List[Any] = []
        for each in inputs:
            if each["indexed"]:
                topic = next(topics)
                if self.is_dynamic_type(each["type"]) or topic is None:
                    r.append(topic)
                else:
                    r.append(Coder.decode_single(each["type"], topic))
            else:
                r.append(next(unindexed_params))

        try:
            next(unindexed_params)
        except StopIteration:
            pass
        else:  # pragma: no cover
            raise ValueError("Wrong unindexed parameters count, internal error.")

        NewType = self._make_output_namedtuple_type("OutType", inputs)
        return NewType(*r)

    @deprecated_to_property
    def get_signature(self) -> bytes:
        """Get signature.

        .. customtox-exclude::

        .. deprecated:: 2.0.0
            Use :attr:`signature` property instead
        """
        return self.signature
