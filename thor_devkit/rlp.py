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

But in the real world, the inputs are not pure bytes.
Some are of complex key-value pairs like dict.
Some are of "0x123" form of number.

This module exists for some pre-defined
real world object => "item" conversion.

                         serialize
 "real world object" +--------------> item

'''
from typing import Union
import re
from rlp.sedes import BigEndianInt
from rlp.exceptions import DeserializationError, SerializationError


def _is_hex_string(a: str) -> bool:
    c = re.compile('^0x[0-9a-f]+$', re.I)
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


class NumericKind(BigEndianInt):
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
            if _is_hex_string(obj):
                number = int(obj, 16)

            if _is_decimal_string(obj):
                number = int(obj)

        if _is_pure_int(obj):
            number = obj

        return super().serialize(number)

    def deserialize(self, serial):
        pass


def pack(obj, profile):
    pass


def unpack(packed, profile):
    pass
