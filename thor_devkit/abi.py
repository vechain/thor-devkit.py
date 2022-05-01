"""
ABI Module.

ABI structure the "Functions" and "Events".

ABI also encode/decode params for functions.

See:
https://github.com/ethereum/wiki/wiki/Ethereum-Contract-ABI

"Function Selector":
sha3("funcName(uint256,address)") -> cut out first 4 bytes.

"Argument Encoding":

Basic:
uint<M> M=8,16,...256
int<M> M=8,16,...256
address
bool
fixed<M>x<N> fixed256x18
ufixed<M>x<N> ufixed256x18
bytes<M> bytes32
function 20bytes address + 4 bytes signature.

Fixed length:
<type>[M] Fix sized array. int[10], uint256[33],

Dynamic length:
bytes
string
<type>[]
"""

import sys
from abc import ABC, abstractmethod
from collections import namedtuple
from typing import (
    Any,
    Dict,
    Generic,
    List,
    NamedTuple,
    Optional,
    TypeVar,
    Union,
    cast,
    overload,
)

import eth_abi
import eth_utils
import voluptuous
from voluptuous import Schema

from .cry import keccak256
from .deprecation import deprecated_to_property

if sys.version_info < (3, 8):
    from typing_extensions import Literal, TypedDict
else:
    from typing import Literal, TypedDict


MUTABILITY = Schema(voluptuous.Any("pure", "view", "payable", "nonpayable"))


def _FUNC_PARAMETER(value):
    return FUNC_PARAMETER(value)


FUNC_PARAMETER = Schema(
    {
        "name": str,
        "type": str,
        voluptuous.Optional("internalType"): str,
        # if the "type" field is "tuple" or "type[]"
        voluptuous.Optional("components"): [_FUNC_PARAMETER],
    },
    required=True,
)


class _FuncParameterT(TypedDict):
    name: str
    type: str  # noqa: A003


class FuncParameterT(_FuncParameterT, total=False):
    internalType: str  # noqa: N815
    # Recursive types aren't really supported, but do partially work
    # This will be expanded a few times and then replaced with Any (deeply nested)
    components: List["FuncParameterT"]  # type: ignore[misc]


FUNCTION = Schema(
    {
        "type": "function",
        "name": str,
        "stateMutability": MUTABILITY,
        "inputs": [FUNC_PARAMETER],
        "outputs": [FUNC_PARAMETER],
    },
    required=True,
)


class FunctionT(TypedDict):
    type: Literal["function"]  # noqa: A003
    name: str
    stateMutability: Literal["pure", "view", "payable", "nonpayable"]  # noqa: N815
    inputs: List["FuncParameterT"]
    outputs: List["FuncParameterT"]


EVENT_PARAMETER = Schema(
    {
        "name": str,
        "type": str,
        voluptuous.Optional("components"): list,
        "indexed": bool,
        voluptuous.Optional("internalType"): str,  # since 0.5.11+
    },
    required=True,
)


class _EventParameterT(_FuncParameterT):
    indexed: bool


class EventParameterT(_EventParameterT, total=False):
    internalType: str  # noqa: N815
    # Recursive types aren't really supported, but do partially work
    # This will be expanded a few times and then replaced with Any (deeply nested)
    components: List["EventParameterT"]  # type: ignore[misc]


EVENT = Schema(
    {
        "type": "event",
        "name": str,
        voluptuous.Optional("anonymous"): bool,
        "inputs": [EVENT_PARAMETER],
    }
)


class _EventT(TypedDict):
    type: Literal["event"]  # noqa: A003
    name: str
    inputs: list["EventParameterT"]


class EventT(_EventT, total=False):
    anonymous: bool


class FunctionResultMixin:
    def to_dict(self) -> Dict[str, Any]:
        return {
            k: (
                v.to_dict()
                if isinstance(v, FunctionResultMixin)
                else ([v_.to_dict() for v_ in v] if isinstance(v, list) else v)
            )
            for k, v in self._asdict().items()  # type: ignore[attr-defined]
        }


def calc_function_selector(abi_json: FunctionT) -> bytes:
    """Calculate the function selector (4 bytes) from the abi json"""
    f = FUNCTION(abi_json)
    return eth_utils.function_abi_to_4byte_selector(f)


def calc_event_topic(abi_json: EventT) -> bytes:
    """Calculate the event log topic (32 bytes) from the abi json"""
    e = EVENT(abi_json)
    return eth_utils.event_abi_to_log_topic(e)


class Coder:
    @staticmethod
    def encode_list(types: List[str], values: List[Any]) -> bytes:
        """Encode a sequence of values, into a single bytes"""
        return eth_abi.encode_abi(types, values)

    @staticmethod
    def decode_list(types: List[str], data: bytes) -> List[Any]:
        """Decode the data, back to a (,,,) tuple"""
        return list(eth_abi.decode_abi(types, data))

    @staticmethod
    def encode_single(t: str, value: Any) -> bytes:
        """Encode value of type t into single bytes"""
        return Coder.encode_list([t], [value])

    @staticmethod
    def decode_single(t: str, data: bytes) -> Any:
        """Decode data of type t back to a single object"""
        return Coder.decode_list([t], data)[0]


# The first should be right, but results in a crash.
# See https://github.com/python/mypy/issues/8320
# _ParamT = TypeVar("_ParamT", EventParameterT, FuncParameterT)
_ParamT = TypeVar("_ParamT", bound=_FuncParameterT)
_BaseT = TypeVar("_BaseT")


class Encodable(Generic[_ParamT], ABC):
    _definition: FunctionT | EventT

    @property
    def name(self) -> str:
        return self._definition["name"]

    @deprecated_to_property
    def get_name(self) -> str:
        return self.name

    @abstractmethod
    def encode(self, parameters: List[Any]) -> Union[bytes, str, List[Optional[bytes]]]:
        raise NotImplementedError()

    @abstractmethod
    def decode(self, __data: bytes) -> NamedTuple:
        raise NotImplementedError()

    @classmethod
    def make_proper_type(cls, elem: _ParamT) -> str:
        """Convert dictionary type repr to type string (inline tuples)"""
        if not elem["type"].startswith("tuple"):
            return elem["type"]

        return (
            "({})".format(
                ",".join(
                    cls.make_proper_type(x)
                    # cast is required thanks to unbound variable
                    for x in cast(list[_ParamT], elem.get("components", []))
                ),
            )
            + elem["type"][5:]
        )
        # It is elem["type"].removeprefix("tuple"), but compat. with python <3.9

    @staticmethod
    def _make_output_namedtuple_type(name: str, types: list) -> type:
        top_names = [(t["name"] or f"ret_{i}") for i, t in enumerate(types)]
        return type(name, (namedtuple(name, top_names), FunctionResultMixin), {})

    @staticmethod
    def get_array_dimensions_count(type_: str) -> int:
        # We don't have to support nested stuff like (uint256, bool[4])[],
        # because type in JSON will be tuple[], uint256 and bool[4] in this case
        # without nesting in string
        return type_.count("[")

    def apply_recursive_names(
        self,
        value,
        typeinfo: _ParamT,
        chain: Optional[List[str]] = None,
        array_depth: int = 0,
    ) -> Union[NamedTuple, List[NamedTuple], Any]:
        """Convert dictionary type repr to type string (inline tuples)"""
        type_ = typeinfo["type"]

        if not type_.startswith("tuple"):
            return value

        chain = [*(chain or []), typeinfo["name"].title() or "NoName"]

        if self.get_array_dimensions_count(type_) > array_depth:
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
    _definition: FunctionT

    def __init__(self, f_definition: FunctionT) -> None:
        """Initialize a function by definition.

        Parameters
        ----------
        f_definition : dict
            See FUNCTION type in this document.
        """
        self._definition = FUNCTION(f_definition)  # Protect.
        self._selector = calc_function_selector(f_definition)  # first 4 bytes.

    @property
    def selector(self) -> bytes:
        return self._selector

    @deprecated_to_property
    def get_selector(self) -> bytes:
        return self.selector

    @overload
    def encode(self, parameters: List[Any], to_hex: Literal[True]) -> str:
        ...

    @overload
    def encode(self, parameters: List[Any], to_hex: Literal[False] = ...) -> bytes:
        ...

    @overload
    def encode(self, parameters: List[Any], to_hex: bool) -> Union[bytes, str]:
        ...

    def encode(self, parameters: List[Any], to_hex: bool = False) -> Union[bytes, str]:
        """Encode the parameters according to the function definition.

        Parameters
        ----------
        parameters : List
            A list of parameters waiting to be encoded.
        to_hex : bool, optional
            If the return should be '0x...' hex string, by default False

        Returns
        -------
        Union[bytes, str]
            Return bytes or '0x...' hex string if needed.
        """
        my_types = [self.make_proper_type(x) for x in self._definition["inputs"]]
        my_bytes = self.selector + Coder.encode_list(my_types, parameters)
        if to_hex:
            return "0x" + my_bytes.hex()
        else:
            return my_bytes

    def decode(self, output_data: bytes) -> NamedTuple:
        """Decode function call output data back into human readable results.

        The result is in dual format. Contains both position and named index.
        eg. { '0': 'john', 'name': 'john' }
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


class Event(Encodable[EventParameterT]):
    _definition: EventT

    def __init__(self, e_definition: dict):
        """Initialize an Event with definition.

        Parameters
        ----------
        e_definition : dict
            A dict with style of EVENT.
        """
        self._definition = EVENT(e_definition)
        self._signature = calc_event_topic(self._definition)

        self.indexed_params = [x for x in self._definition["inputs"] if x["indexed"]]

        if len(self.indexed_params) - int(self.is_anonymous) > 3:
            raise ValueError("Too much indexed parameters!")

    @property
    def is_anonymous(self) -> bool:
        return self._definition.get("anonymous", False)

    @property
    def signature(self) -> bytes:
        return self._signature

    @deprecated_to_property
    def get_signature(self) -> bytes:
        return self.signature

    @classmethod
    def is_dynamic_type(cls, t: str):
        """Check if the input type is dynamic"""
        return t == "bytes" or t == "string" or "[" in t or t.startswith("tuple")

    @staticmethod
    def strip_dynamic_part(type_: str) -> str:
        if "[" in type_:
            return type_[: type_.index("[")]
        return type_

    @staticmethod
    def pad(data: list[bytes] | bytes, mod: int, to: Literal["r", "l"] = "l") -> bytes:
        if not isinstance(data, bytes):
            data = b"".join(data)

        length = len(data)
        missing = (mod * (length // mod + 1) - length) % mod
        if to == "l":
            return data + missing * b"\x00"
        else:
            return missing * b"\x00" + data

    @classmethod
    def dynamic_type_to_topic(
        cls, type_: dict, value, array_depth: int = 0
    ) -> list[bytes]:
        t_type = type_["type"]
        if cls.get_array_dimensions_count(t_type) > array_depth:
            return [
                cls.pad(cls.dynamic_type_to_topic(type_, v, array_depth + 1), 32, "l")
                for v in value
            ]

        if t_type.startswith("tuple"):
            return [
                cls.pad(cls.dynamic_type_to_topic(t, v, array_depth), 32, "l")
                for t, v in zip(type_["components"], value)
            ]

        if t_type == "string":
            assert isinstance(value, str), 'Value of type "string" must be str'
            return [value.encode("utf-8")]
        elif t_type == "bytes":
            assert isinstance(value, bytes), 'Value of type "bytes" must be bytes'
            return [value]
        else:
            return [Coder.encode_single(cls.strip_dynamic_part(t_type), value)]

    def encode(
        self, parameters: Union[Dict[str, Any], List[Any]]
    ) -> List[Optional[bytes]]:
        """Assemble indexed keys into topics.

        Usage
        -----

        Commonly used to filter out logs of concerned topics,
        eg. To filter out VIP180 transfer logs of a certain wallet, certain amount.

        Parameters
        ----------
        parameters : Union[dict, List]
            A dict/list of indexed param of the given event,
            fill in None to occupy the position,
            if you aren't sure about the value.

            eg. For event:

            EventName(address from indexed, address to indexed, uint256 value)

            the parameters can be:
            ['0xa32f..ff', '0x1f...ac']
            or:
            {'from': '0xa32f..ff', 'to': '0x1f...ac'}
            or:
            [None, '0x1f...ac']
            or:
            {'from': None, 'to': '0x1f...ac'}

        Returns
        -------
        List
            [description]

        Raises
        ------
        ValueError
            [description]
        """
        topics: List[Optional[bytes]] = []

        # not anonymous? topic[0] = signature.
        if not self.is_anonymous:
            topics.append(self.signature)

        has_no_name_param = any(True for x in self.indexed_params if not x["name"])

        # Disallow lists of unnamed parameters
        if not isinstance(parameters, list) and has_no_name_param:
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

        def parse(param, definition):
            if self.is_dynamic_type(definition["type"]):
                return keccak256(self.dynamic_type_to_topic(definition, param))[0]
            else:
                return Coder.encode_single(
                    self.make_proper_type(definition),
                    param,
                )

        if isinstance(parameters, list):
            for param, definition in zip(parameters, self.indexed_params):
                topics.append(parse(param, definition))

        if isinstance(parameters, dict):
            for definition in self.indexed_params:
                param = parameters.get(definition["name"])
                topics.append(param if param is None else parse(param, definition))

        return topics

    def decode(
        self,
        data: bytes,
        topics: Optional[List[Optional[bytes]]] = None,
        strict: bool = True,
    ) -> NamedTuple:
        """Decode "data" according to the "topic"s.

        One output can contain an array of logs.
        One log contains mainly 3 entries:

        - For a non-indexed parameters event:

            "address": The emitting contract address.
            "topics": [
                "signature of event"
            ]
            "data": "0x..." (contains parameters value)

        - For an indexed parameters event:

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
        the "topics" list, hence topics[0] is not the signature.
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
                topics = (topics or []) + [None] * (indexed_count - topics_count)
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
