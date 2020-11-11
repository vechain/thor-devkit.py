'''
RLP Encoding/Decoding.

RLP encodes before storing on disk or transmitting on network.

Primary RLP can only deal with "item" type,
The definition of item is:
1) byte string (bytes in Python)
2) list

Some exmples are:
- b'\x00\xff'
- empty list []
- list of bytes [ b'\x00', b'\x01\x03']
- list of combinations [ [], b'\x00', [b'\x00']]

The encoded result is bytes. The encoded methods is called RLP.

         RLP    +-----------+
 item +-------> |RPL encoded|
                +-----------+

But in the real world, the inputs are not pure bytes nor lists.
Some are of complex key-value pairs like dict.
Some are of "0x123" form of number.

This module exists for some pre-defined
real world object => "item" conversion.

                         serialize
 "real world object" +--------------> item

'''
from typing import Tuple
from typing import Union
from typing import List
from typing import Any
import re
from rlp.sedes import BigEndianInt
from rlp.exceptions import DeserializationError, SerializationError
from rlp import encode as rlp_encode
from rlp import decode as rlp_decode


def _is_hex_string(a: str, must_contain_data: bool) -> bool:
    c = None
    if must_contain_data:
        c = re.compile('^0x[0-9a-f]+$', re.I)
    else:
        c = re.compile('^0x[0-9a-f]*$', re.I)

    if c.match(a):
        return True
    else:
        return False


def _is_decimal_string(a: str) -> bool:
    c = re.compile('^[0-9]+$')
    if c.match(a):
        return True
    else:
        return False


def _is_pure_int(a: int) -> bool:
    return type(a) == int


def _is_pure_str(a: str) -> bool:
    return type(a) == str


class ScalarKind():
    pass


class BytesKind(ScalarKind):
    '''
    Convert bytes type of Python object to RLP "item".
    '''
    @classmethod
    def is_valid_type(cls, obj):
        return isinstance(obj, (bytes, bytearray))

    def serialize(self, obj: bytes) -> bytes:
        '''
        Serialize the object into a RLP encode-able "item".

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
        SerializationError
            raise if input is not bytes.
        '''
        if not self.is_valid_type(obj):
            raise SerializationError(
                'type of "obj" param is not right, bytes required.', obj)

        return obj

    def deserialize(self, serial: bytes) -> bytes:
        '''
        De-serialize a RLP "item" back to bytes.

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
        DeserializationError
            raise if input is not bytes.
        '''
        if not self.is_valid_type(serial):
            raise DeserializationError(
                'type of "serial" param is not right, bytes required.', serial)

        return serial


class NumericKind(ScalarKind, BigEndianInt):
    '''
    This is a pre-defined type for Number-like objects.

    Good examples are:
    '0x0', '0x123', '0', '100', 0, 0x123

    Bad examples are:
    '0x123z', {}, '0x', -1, '0x12345678123456780', 2 ** 64
    '''

    def __init__(self, max_bytes: int = None):
        '''
        Initialize a NumericKind.

        Parameters
        ----------
        max_bytes : int
            Max bytes in the encoded result. (not enough then prepend 0)
        '''
        self.max_bytes = max_bytes
        super().__init__(l=max_bytes)

    def serialize(self, obj: Union[str, int]) -> bytes:
        '''
        Serialize the object into a RLP encode-able "item".

        Parameters
        ----------
        obj : Union[str, int]
            obj is either number in string or number int.
        '''

        if not (_is_pure_str(obj) or _is_pure_int(obj)):
            raise SerializationError("The input is not str nor int.", obj)

        number = None

        if _is_pure_str(obj):
            if _is_hex_string(obj, True):
                number = int(obj, 16)

            if _is_decimal_string(obj):
                number = int(obj)

        if _is_pure_int(obj):
            number = obj

        # remove leading 0 from bytes sequence.
        result_bytes = super().serialize(number)
        byte_list = []
        can_append_flag = False
        for x in result_bytes:
            if not can_append_flag:
                if x != 0:
                    can_append_flag = True
                else:
                    continue

            if can_append_flag:
                byte_list.append(x)

        return bytes(byte_list)

    def deserialize(self, serial) -> int:
        '''
        Deserialize bytes to int.

        Parameters
        ----------
        serial : [type]
            bytes

        Returns
        -------
        int
            integer

        Raises
        ------
        DeserializationError
            If bytes contain leading 0.
        '''
        if len(serial) > 0 and serial[0] == 0:
            raise DeserializationError(
                "Leading 0 should be removed from bytes",
                serial
            )

        # add leading 0 to bytes sequence if width is set.
        if self.max_bytes:
            byte_list = [x for x in serial]
            length = len(byte_list)
            missed = self.max_bytes - length
            if missed:
                byte_list = [0] * missed + byte_list
            serial2 = bytes(byte_list)
        else:
            serial2 = serial
        return super().deserialize(serial2)


class BlobKind(ScalarKind):
    '''
    This is a pre-defined type for '0x....' like hex strings,
    which shouldn't be interpreted as a number, usually an identifier.

    like: address, block_ref, data to smart contract.
    '''

    def serialize(self, obj: str) -> bytes:
        '''
        Serialize a '0x...' string to bytes.

        Parameters
        ----------
        obj : str
            '0x...' style string.

        Returns
        -------
        bytes
            the "item" that can be rlp encodeded.
        '''
        if not _is_hex_string(obj, False):
            raise SerializationError('expect 0x... style string', obj)

        if len(obj) % 2 != 0:
            raise SerializationError(
                'expect 0x... style string of even length.', obj)

        obj2 = obj[2:]  # remove '0x'

        return bytes.fromhex(obj2)

    def deserialize(self, serial: bytes) -> str:
        '''
        Deserialize bytes to '0x...' string.

        Parameters
        ----------
        serial : bytes
            the bytes.

        Returns
        -------
        str
            string of style '0x...'
        '''

        return '0x' + serial.hex()


class FixedBlobKind(BlobKind):
    '''
    This is a pre-defined type for '0x....' like hex strings,
    which shouldn't be interpreted as a number, usually an identifier.

    like: address, block_ref, data to smart contract.

    Note
    ----
        This kind has a fixed length of bytes.
        (also means the input hex is fixed length)
    '''

    def __init__(self, byte_length):
        self.byte_length = byte_length

    def serialize(self, obj: str) -> bytes:
        # 0x counts for 2 chars. 1 bytes = 2 hex char.
        allowed_hex_length = self.byte_length * 2 + 2

        if len(obj) != allowed_hex_length:
            raise SerializationError(
                "Max allowed string length {}".format(allowed_hex_length),
                obj
            )

        return super().serialize(obj)

    def deserialize(self, serial: bytes) -> str:
        if len(serial) != self.byte_length:
            raise DeserializationError(
                "Bytes should be {} long.".format(self.byte_length),
                serial
            )

        return super().deserialize(serial)


class NoneableFixedBlobKind(FixedBlobKind):
    '''
    This is a pre-defined type for '0x....' like hex strings,
    which shouldn't be interpreted as a number, usually an identifier.

    like: address, block_ref, data to smart contract.

    Note
    ----
        This kind has a fixed length of bytes.
        (also means the input hex is fixed length)

        For this kind, input can be None.
        Then decoded is also None.
    '''

    def __init__(self, byte_length):
        super().__init__(byte_length)

    def serialize(self, obj: str = None) -> bytes:
        if obj is None:
            return bytes(0)

        return super().serialize(obj)

    def deserialize(self, serial: bytes) -> str:
        if len(serial) == 0:
            return None

        return super().deserialize(serial)


class CompactFixedBlobKind(FixedBlobKind):
    '''
    This is a pre-defined type for '0x....' like strings,
    which shouldn't be interpreted as a number, usually an identifier.

    like: address, block_ref, data to smart contract.

    Note
    ----
        When encode, the result fixed length bytes will be
        removed of leading zeros. i.e. 000123 -> 123

        When decode, it expects the input bytes length <= fixed_length.
        and it pads the leading zeros back. Output '0x{0}paddingxxx...'
    '''

    def __init__(self, byte_length):
        super().__init__(byte_length)

    def serialize(self, obj: str) -> bytes:
        b = super().serialize(obj)
        first_non_zero_index = -1
        for idx, each in enumerate(b):
            if each != 0:
                first_non_zero_index = idx
                break

        b_list = []
        if first_non_zero_index != -1:
            b_list = b[first_non_zero_index:]

        if (len(b_list) == 0):
            return bytes(0)
        else:
            return bytes(b_list)

    def deserialize(self, serial: bytes) -> str:
        if (len(serial) > self.byte_length):
            raise DeserializationError(
                "Bytes too long, only need {}".format(self.byte_length),
                serial
            )

        if len(serial) == 0 or serial[0] == 0:
            raise DeserializationError(
                "No leading zeros. And byte sequence length should be > 0",
                serial
            )

        missing = self.byte_length - len(serial)
        b_list = [0] * missing + [x for x in serial]
        return super().deserialize(bytes(b_list))


class BaseWrapper():
    ''' BaseWrapper is a container for complex types to be encode/decoded. '''
    pass


class DictWrapper(BaseWrapper):
    ''' DictWrapper is a container for parsing dict like objects. '''

    def __init__(self, list_of_tuples: List[Tuple[str, Union[BaseWrapper, ScalarKind]]]):
        '''Constructor

        Parameters
        ----------
        list_of_tuples : List[Tuple[str, Union[BaseWrapper, ScalarKind]]]
            A list of tuples.
            eg. [(key, codec), (key, codec) ... ])
            key is a string.
            codec is either a BaseWrapper, or a ScalarKind.
        '''
        self.keys = [x[0] for x in list_of_tuples]
        self.codecs = [x[1] for x in list_of_tuples]


class ListWrapper(BaseWrapper):
    '''
    ListWrapper is a container for parsing a list,
    the items type in the list can be heterogeneous.
    '''

    def __init__(self, list_of_codecs: List[Union[BaseWrapper, ScalarKind]]):
        '''Constructor

        Parameters
        ----------
        list_of_codecs : List[Union[BaseWrapper, ScalarKind]]
            A list of codecs.
            eg. [codec, codec, codec...]
            codec is either a BaseWrapper, or a ScalarKind.
        '''
        self.codecs = list_of_codecs


class HomoListWrapper(BaseWrapper):
    '''
    HomoListWrapper is a container for parsing a list,
    the items in the list are of the same type.
    '''

    def __init__(self, codec: Union[BaseWrapper, ScalarKind]):
        '''Constructor

        Parameters
        ----------
        list_of_codecs : List[Union[BaseWrapper, ScalarKind]]
            A list of codecs.
            eg. [codec, codec, codec...]
            codec is either a BaseWrapper, or a ScalarKind.
        '''
        self.codec = codec


def pack(obj, wrapper: Union[BaseWrapper, ScalarKind]) -> Union[bytes, List]:
    '''Pack a Python object according to wrapper.

    Parameters
    ----------
    obj : Any
        A dict, a list, or a string/int/any...
    wrapper : Union[BaseWrapper, ScalarKind]
        A Wrapper.

    Returns
    -------
    Union[bytes, List]
        Returns either the bytes if obj is a basic type,
        or a list if obj is dict/list.

    Raises
    ------
    Exception
        If the wrapper/codec is unknown.
    '''
    # Simple wrapper: ScalarKind
    if isinstance(wrapper, ScalarKind):
        return wrapper.serialize(obj)

    # Complicated wrapper: BaseWrapper
    if isinstance(wrapper, BaseWrapper):
        if isinstance(wrapper, DictWrapper):
            r = []
            for (key, codec) in zip(wrapper.keys, wrapper.codecs):
                r.append(pack(obj[key], codec))
            return r

        if isinstance(wrapper, ListWrapper):
            r = []
            for (item, codec) in zip(obj, wrapper.codecs):
                r.append(pack(item, codec))
            return r

        if isinstance(wrapper, HomoListWrapper):
            r = []
            for item in obj:
                r.append(pack(item, wrapper.codec))
            return r

        raise Exception('codec type is unknown.')

    # Wrapper type is unknown, raise.
    raise Exception('wrapper type is unknown.{}'.format(wrapper))


def unpack(packed: Union[List, bytes], wrapper: Union[BaseWrapper, ScalarKind]) -> Union[dict, List, Any]:
    '''Unpack a serialized thing back into a dict/list or a Python basic type.

    Parameters
    ----------
    packed : Union[List, bytes]
        A list of RLP encoded or pure bytes.
    wrapper : Union[BaseWrapper, ScalarKind]
        The Wrapper.

    Returns
    -------
    Union[dict, List, Any]
        dict/list if the wrapper instruction is dict/list,
        Python basic type if input is bytes.

    Raises
    ------
    Exception
        If the wrapper/codec is unknown.
    '''
    # Simple wrapper: ScalarKind
    if isinstance(wrapper, ScalarKind):
        return wrapper.deserialize(packed)

    # Complicated wrapper: BaseWrapper
    if isinstance(wrapper, BaseWrapper):
        if isinstance(wrapper, DictWrapper):
            r = {}
            for (blob, key, codec) in zip(packed, wrapper.keys, wrapper.codecs):
                r[key] = unpack(blob, codec)
            return r

        if isinstance(wrapper, ListWrapper):
            r = []
            for (blob, codec) in zip(packed, wrapper.codecs):
                r.append(unpack(blob, codec))
            return r

        if isinstance(wrapper, HomoListWrapper):
            r = []
            for blob in packed:
                r.append(unpack(blob, wrapper.codec))
            return r

        raise Exception('codec type is unknown.')

    # Wrapper type is unknown, raise.
    raise Exception('wrapper type is unknown.')


class ComplexCodec(object):
    def __init__(self, wrapper: BaseWrapper):
        self.wrapper = wrapper

    def encode(self, data: Any) -> bytes:
        packed = pack(data, self.wrapper)
        return rlp_encode(packed)

    def decode(self, data: bytes):
        to_be_unpacked = rlp_decode(data)
        return unpack(to_be_unpacked, self.wrapper)
