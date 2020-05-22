import pytest
from rlp.exceptions import DeserializationError, SerializationError
from thor_devkit import rlp as m_rlp


def test_numericKind_encode():
    # Set up a max 8 bytes width NumericKind.
    kind = m_rlp.NumericKind(8)

    # Should pass
    assert kind.serialize('0x0').hex() == ''
    assert kind.serialize('0x123').hex() == '0123'
    assert kind.serialize('0').hex() == ''
    assert kind.serialize('100').hex() == '64'
    assert kind.serialize(0).hex() == ''
    assert kind.serialize(0x123).hex() == '0123'

    # Should Throw
    with pytest.raises(SerializationError):
        kind.serialize('0x123z')

    with pytest.raises(SerializationError):
        kind.serialize({})

    with pytest.raises(SerializationError):
        kind.serialize('0x')

    with pytest.raises(SerializationError):
        kind.serialize(-1)

    with pytest.raises(SerializationError):
        kind.serialize('0x12345678123456780')

    # We won't hit this exception because big int are safe in Python.
    # with pytest.raises(SerializationError):
    #     kind.serialize(2 ** 64)


def test_numericKind_decode():
    # Set up a max 8 bytes width NumericKind.
    kind = m_rlp.NumericKind(8)

    # Should pass.
    assert kind.deserialize(bytes(0)) == 0
    assert kind.deserialize(bytes([1, 2, 3])) == int('0x010203', 16)
    assert kind.deserialize(bytes([1, 2, 3, 4, 5, 6, 7, 8])) == int(
        '0x102030405060708', 16)

    # Should fail.
    with pytest.raises(DeserializationError):
        kind.deserialize(bytes([1] * 9))

    with pytest.raises(DeserializationError):
        kind.deserialize(bytes([0, 1, 2]))
