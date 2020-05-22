import pytest
from rlp.exceptions import DeserializationError, SerializationError
from thor_devkit import rlp as m_rlp


def test_bytesKind():
    kind = m_rlp.BytesKind()

    assert kind.serialize(bytes.fromhex('ff')) == b'\xff'
    assert kind.serialize(bytes.fromhex('01ff')) == b'\x01\xff'

    assert kind.deserialize(bytes.fromhex('ff')) == b'\xff'
    assert kind.deserialize(bytes.fromhex('01ff')) == b'\x01\xff'

    with pytest.raises(SerializationError):
        kind.serialize(1)

    with pytest.raises(SerializationError):
        kind.serialize('0x1234')


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
    # Max Integer problem in Javascript: 2^53 -1
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/isSafeInteger
    # No such problem in Python:
    # https://stackoverflow.com/questions/7604966/maximum-and-minimum-values-for-ints
    #
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


def test_blobKind_encode():
    kind = m_rlp.BlobKind()
    assert kind.serialize('0x1234567890').hex() == '1234567890'

    with pytest.raises(SerializationError, match=".+even.+"):
        kind.serialize('0x1')

    with pytest.raises(SerializationError):
        kind.serialize('0xxy')

    with pytest.raises(Exception):
        kind.serialize(1)


def test_blobKind_decode():
    kind = m_rlp.BlobKind()

    assert kind.deserialize(bytes([1, 2, 3, 4, 5])) == '0x0102030405'


def test_fixedBlob_encode():
    kind = m_rlp.FixedBlobKind(4)

    assert kind.serialize('0x12345678').hex() == '12345678'

    with pytest.raises(SerializationError):
        kind.serialize('0x1234567z')

    with pytest.raises(SerializationError):
        kind.serialize('0x1234567890')

    with pytest.raises(SerializationError):
        kind.serialize('0x1234567')

    with pytest.raises(Exception):
        kind.serialize(1)

    with pytest.raises(Exception):
        kind.serialize(None)


def test_fixedBlob_decode():
    kind = m_rlp.FixedBlobKind(4)

    assert kind.deserialize(bytes([1, 2, 3, 4])) == '0x01020304'

    with pytest.raises(DeserializationError):
        kind.deserialize(bytes([0, 0]))

    with pytest.raises(DeserializationError):
        kind.deserialize(bytes(0))


def test_noneableFixedBlobKind_encode():
    kind = m_rlp.NoneableFixedBlobKind(4)

    assert kind.serialize(None).hex() == ''
    assert kind.serialize('0x12345678').hex() == '12345678'

    with pytest.raises(SerializationError):
        kind.serialize('0x1234567z')

    with pytest.raises(SerializationError):
        kind.serialize('0x11')

    with pytest.raises(SerializationError):
        kind.serialize('0x1234567890')

    with pytest.raises(SerializationError):
        kind.serialize('0x1234567')

    with pytest.raises(Exception):
        kind.serialize(1)

    with pytest.raises(SerializationError):
        kind.serialize('0x')


def test_noneableFixedBlobKind_decode():
    kind = m_rlp.NoneableFixedBlobKind(4)

    assert kind.deserialize(bytes(0)) is None
    assert kind.deserialize(bytes([1, 2, 3, 4])) == '0x01020304'

    with pytest.raises(DeserializationError):
        kind.deserialize(bytes([0, 0]))


def test_compact_fixed_blobkind_encode():
    kind = m_rlp.CompactFixedBlobKind(4)
    assert kind.serialize('0x00112233').hex() == '112233'


def test_compact_fixed_blobkind_decode():
    kind = m_rlp.CompactFixedBlobKind(4)
    assert kind.deserialize(bytes([1])) == '0x00000001'


def test_compact_fixed_blobkind_encode_with_zero():
    kind = m_rlp.CompactFixedBlobKind(4)
    assert kind.serialize('0x00000000').hex() == ''
