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
    # zero leading
    assert kind.serialize('0x00112233').hex() == '112233'
    # zero in the middle
    assert kind.serialize('0x11002233').hex() == '11002233'

def test_compact_fixed_blobkind_decode():
    kind = m_rlp.CompactFixedBlobKind(4)
    # should prefix the zeros
    assert kind.deserialize(bytes([1])) == '0x00000001'
    # should prefix the zeros, and the middle zeros should not interfer.
    assert kind.deserialize(bytes.fromhex('110022')) == '0x00110022'


def test_compact_fixed_blobkind_encode_with_zero():
    kind = m_rlp.CompactFixedBlobKind(4)
    assert kind.serialize('0x00000000').hex() == ''


def test_rlp_complex():
    my_data = {
        "foo": 123,
        "bar": '0x12345678',
        "baz": [
            { "x": '0x11', "y": 1234 },
            { "x": '0x12', "y": 5678 }
        ]
    }

    my_wrapper = m_rlp.DictWrapper([
        ("foo", m_rlp.NumericKind()),
        ("bar", m_rlp.FixedBlobKind(4)),
        ("baz", m_rlp.ListWrapper(
                    list_of_codecs=[
                        m_rlp.DictWrapper([
                            ("x", m_rlp.BlobKind()),
                            ("y", m_rlp.NumericKind())
                        ]),
                        m_rlp.DictWrapper([
                            ("x", m_rlp.BlobKind()),
                            ("y", m_rlp.NumericKind())
                        ])
                    ]
                )
        )
    ])

    cc = m_rlp.ComplexCodec(my_wrapper)

    assert cc.encode(my_data).hex() == 'd17b8412345678cac4118204d2c41282162e'

    assert cc.decode(bytes.fromhex('d17b8412345678cac4118204d2c41282162e')) == my_data


def test_rlp_complex_homo():
    my_data = {
        "foo": 123,
        "bar": '0x12345678',
        "baz": [
            { "x": '0x11', "y": 1234 },
            { "x": '0x12', "y": 5678 }
        ]
    }

    my_wrapper = m_rlp.DictWrapper([
        ("foo", m_rlp.NumericKind()),
        ("bar", m_rlp.FixedBlobKind(4)),
        ("baz", m_rlp.HomoListWrapper(
                    codec=m_rlp.DictWrapper([
                        ("x", m_rlp.BlobKind()),
                        ("y", m_rlp.NumericKind())
                    ])
                )
        )
    ])

    cc = m_rlp.ComplexCodec(my_wrapper)

    assert cc.encode(my_data).hex() == 'd17b8412345678cac4118204d2c41282162e'

    assert cc.decode(bytes.fromhex('d17b8412345678cac4118204d2c41282162e')) == my_data


def test_rlp_complex_strange():
    my_data = {
        "foo": 123,
        "bar": '0x12345678',
        "baz": [
            { "x": '0x11', "y": 1234 },
            { "x": '0x12', "y": 5678 },
            789,
            [
                123,
                {
                    "a": 1
                }
            ]
        ]
    }

    my_wrapper = m_rlp.DictWrapper([
        ("foo", m_rlp.NumericKind()),
        ("bar", m_rlp.FixedBlobKind(4)),
        ("baz", m_rlp.ListWrapper([
            m_rlp.DictWrapper([
                ("x", m_rlp.BlobKind()),
                ("y", m_rlp.NumericKind())
            ]),
            m_rlp.DictWrapper([
                ("x", m_rlp.BlobKind()),
                ("y", m_rlp.NumericKind())
            ]),
            m_rlp.NumericKind(),
            m_rlp.ListWrapper([
                m_rlp.NumericKind(),
                m_rlp.DictWrapper([
                    ("a", m_rlp.NumericKind())
                ])
            ])
        ]))
    ])

    cc = m_rlp.ComplexCodec(my_wrapper)

    my_bytes = cc.encode(my_data) # encode
    assert cc.decode(my_bytes) == my_data # decode