r"""ABI encoding module."""

import sys
import warnings
from abc import ABC, abstractmethod
from collections import namedtuple
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Generic,
    Iterable,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
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
from thor_devkit.cry.utils import _with_doc_mro
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
    "_ParameterT",
    "MUTABILITY",
    "StateMutabilityT",
    "FUNC_PARAMETER",
    "FuncParameterT",
    "FUNCTION",
    "FunctionT",
    "EVENT_PARAMETER",
    "EventParameterT",
    "EVENT",
    "EventT",
    "Coder",
    "Function",
    "Event",
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
    """:class:`~typing.NamedTuple` mixin with convenience methods.

    It is returned from :meth:`Event.decode` and :meth:`Function.decode`.

    When obtained from ``decode`` method of :class:`Function` or :class:`Event`,
    this class will contain decoded parameters. They can be obtained either by name
    (name will be taken from JSON input or ``ret_{index}`` if name was missing)
    or by numeric index as from plain tuples.

    .. versionadded:: 2.0.0

    Notes
    -----
    Type checker will consider all attributes ``Any``
    due to implementation limitation.

    See Also
    --------
    :meth:`Function.decode`: for examples of items access
    """

    def to_dict(self) -> Dict[str, Any]:
        """Return dictionary representation (recursively).

        Returns
        -------
        Dict[str, Any]
            Dictionary of form ``{name: value}``
            (all inner namedtuples are converted too)
        """
        return {
            k: (
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
        top_names = [(t["name"] or f"ret_{i}") for i, t in enumerate(types)]
        return type(name, (namedtuple(name, top_names), FunctionResult), {})

    @staticmethod
    def _get_array_dimensions_count(type_: str) -> int:
        # We don't have to support nested stuff like (uint256, bool[4])[],
        # because type in JSON will be tuple[], uint256 and bool[4] in this case
        # without nesting in string
        return type_.count("[")

    def apply_recursive_names(
        self,
        value: Any,
        typeinfo: _ParamT,
        chain: Optional[Sequence[str]] = None,
        array_depth: int = 0,
    ) -> Union[FunctionResult, List[FunctionResult], Any]:
        """Build namedtuple from values.

        .. customtox-exclude::
        """
        type_ = typeinfo["type"]

        if not type_.startswith("tuple"):
            return value

        chain = [*(chain or []), typeinfo["name"].title() or "NoName"]

        if self._get_array_dimensions_count(type_) > array_depth:
            return [
                self.apply_recursive_names(v, typeinfo, chain[:-1], array_depth + 1)
                for v in value
            ]

        components = cast(list[_ParamT], typeinfo.get("components", []))
        NewType = self._make_output_namedtuple_type("_".join(chain), components)
        return NewType(
            *(
                self.apply_recursive_names(v, t, chain)
                for t, v in zip(components, value)
            )
        )


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
    def encode(self, parameters: Sequence[Any], to_hex: Literal[True]) -> str:
        ...

    @overload
    def encode(self, parameters: Sequence[Any], to_hex: Literal[False] = ...) -> bytes:
        ...

    @overload
    def encode(self, parameters: Sequence[Any], to_hex: bool) -> Union[bytes, str]:
        ...

    def encode(
        self, parameters: Sequence[Any], to_hex: bool = False
    ) -> Union[bytes, str]:
        """Encode the parameters according to the function definition.

        .. versionchanged:: 2.0.0
            parameter ``to_hex`` is deprecated, use ``"0x" + result.hex()``
            directly instead.

        Parameters
        ----------
        parameters : Sequence of Any
            A list of parameters waiting to be encoded.
        to_hex : bool, default: False
            If the return should be ``0x...`` hex string

        Returns
        -------
        bytes
            By default or if ``to_hex=False`` was passed.
        str
            If ``to_hex=True`` was passed.
        """
        my_types = [self.make_proper_type(x) for x in self._definition["inputs"]]
        my_bytes = self.selector + Coder.encode_list(my_types, parameters)
        if to_hex:
            warnings.warn(
                DeprecationWarning(
                    "to_hex parameter is deprecated. "
                    "Use ``'0x' + output.hex()`` instead to replicate that behaviour"
                )
            )
            return "0x" + my_bytes.hex()
        else:
            return my_bytes

    def decode(self, output_data: bytes) -> FunctionResult:
        """Decode function call output data back into human readable results.

        The result is dynamic subclass of
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
        my_types = [self.make_proper_type(x) for x in self._definition["outputs"]]
        result_list = Coder.decode_list(my_types, output_data)

        outputs = self._definition["outputs"]
        NewType = self._make_output_namedtuple_type("OutType", outputs)
        return NewType(
            *(
                self.apply_recursive_names(value, typeinfo)
                for typeinfo, value in zip(outputs, result_list)
            )
        )

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
    def dynamic_type_to_topic(
        cls, type_: EventParameterT, value: Any, array_depth: int = 0
    ) -> List[bytes]:
        """Encode single value according to given ``type``."""
        t_type = type_["type"]
        if cls._get_array_dimensions_count(t_type) > array_depth:
            return [
                cls._pad(cls.dynamic_type_to_topic(type_, v, array_depth + 1), 32, "l")
                for v in value
            ]

        if t_type.startswith("tuple"):
            return [
                cls._pad(cls.dynamic_type_to_topic(t, v, array_depth), 32, "l")
                for t, v in zip(type_["components"], value)
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
        """Assemble indexed keys into topics.

        Commonly used to filter out logs of concerned topics,
        e.g. To filter out VIP180 transfer logs of a certain wallet, certain amount.

        Parameters
        ----------
        parameters : Mapping[str, Any] or Sequence[Any]
            A dict/list of indexed param of the given event.
            Fill in :class:`None` to occupy the position, if you aren't sure
            about the value.

            e.g. for event defined as::

                EventName(address from indexed, address to indexed, uint256 value)

            the parameters can be::

                ['0xa32f..ff', '0x1f...ac']
                # or
                {'from': '0xa32f..ff', 'to': '0x1f...ac'}
                # or
                [None, '0x1f...ac']
                # or
                {'from': None, 'to': '0x1f...ac'}

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
        """
        topics: List[Optional[bytes]] = []

        # not anonymous? topic[0] = signature.
        if not self.is_anonymous:
            topics.append(self.signature)

        has_no_name_param = any(True for x in self.indexed_params if not x["name"])

        # Disallow dicts for unnamed parameters
        if isinstance(parameters, Mapping) and has_no_name_param:
            raise ValueError(
                "Event definition contains param without a name, use a list"
                " of parameters instead of dict."
            )

        # Check arguments length
        if len(parameters) != len(self.indexed_params):
            raise ValueError(
                "Indexed parameters needs {} items, {} is given.".format(
                    len(self.indexed_params), len(parameters)
                )
            )

        def encode(param: Any, definition: EventParameterT) -> bytes:
            if self.is_dynamic_type(definition["type"]):
                return keccak256(self.dynamic_type_to_topic(definition, param))[0]
            else:
                return Coder.encode_single(self.make_proper_type(definition), param)

        if isinstance(parameters, Mapping):
            for definition in self.indexed_params:
                param = parameters.get(definition["name"])
                topics.append(param if param is None else encode(param, definition))
        elif (
            isinstance(parameters, Sequence)
            and not isinstance(parameters, (bytes, bytearray))
            # bytes are Sequence too!
        ):
            for param, definition in zip(parameters, self.indexed_params):
                topics.append(param if param is None else encode(param, definition))
        else:
            raise TypeError(
                f"Expected sequence or mapping of parameters, got: {type(parameters)}"
            )

        return topics

    def decode(
        self,
        data: bytes,
        topics: Optional[Sequence[Optional[bytes]]] = None,
        strict: bool = True,
    ) -> FunctionResult:
        """Decode "data" according to the "topic"s.

        One output can contain an array of logs.

        Parameters
        ----------
        data : bytes
            Data to decode.
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

            "address": The emitting contract address.
            "topics": [
                "signature of event"
            ]
            "data": "0x..." (contains parameters value)

        - For an indexed parameters event::

            "address": The emitting contract address.
            "topics": [
                "signature of event",
                "indexed param 1",
                "indexed param 2",
                ...
                --> max 3 entries of indexed params.
            ]
            "data": "0x..." (remain un-indexed parameters value)

        If the event is "anonymous" then the signature is not inserted into
        the "topics" list, hence ``topics[0]`` is not the signature.
        """
        if not self.is_anonymous and topics:
            # if not anonymous, topics[0] is the signature of event.
            # we cut it out, because we already have self.signature
            topics = topics[1:]

        unindexed_params_defs = [
            x for x in self._definition["inputs"] if not x["indexed"]
        ]

        indexed_count, topics_count = len(self.indexed_params), len(topics or [])
        if topics is not None and indexed_count != topics_count:
            if not strict and indexed_count > topics_count:
                topics = list(topics or []) + [None] * (indexed_count - topics_count)
            else:
                raise ValueError("Invalid topics count.")
        topics = topics or []

        my_types = list(map(self.make_proper_type, unindexed_params_defs))
        result_list = Coder.decode_list(my_types, data)
        unindexed_params = (
            self.apply_recursive_names(value, typeinfo)
            for typeinfo, value in zip(unindexed_params_defs, result_list)
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
