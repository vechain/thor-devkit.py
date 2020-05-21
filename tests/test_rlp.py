import pytest
from rlp.exceptions import DeserializationError, SerializationError
from thor_devkit import rlp as m_rlp


def test_numericKind_encode():
    # Should pass
    assert m_rlp.NumericKind().serialize('0x0').hex() == ''
    assert m_rlp.NumericKind().serialize('0x123').hex() == '0123'
    assert m_rlp.NumericKind().serialize('0').hex() == ''
    assert m_rlp.NumericKind().serialize('100').hex() == '64'
    assert m_rlp.NumericKind().serialize(0).hex() == ''
    assert m_rlp.NumericKind().serialize(0x123).hex() == '0123'

    # Should Throw
    with pytest.raises(SerializationError):
        m_rlp.NumericKind().serialize('0x123z')

    with pytest.raises(SerializationError):
        m_rlp.NumericKind().serialize({})

    with pytest.raises(SerializationError):
        m_rlp.NumericKind().serialize('0x')

    with pytest.raises(SerializationError):
        m_rlp.NumericKind().serialize(-1)

    with pytest.raises(SerializationError):
        m_rlp.NumericKind(8).serialize('0x12345678123456780')

    # We won't hit this exception because big int are safe in Python.
    # with pytest.raises(SerializationError):
    #     m_rlp.NumericKind().serialize(2 ** 64)
