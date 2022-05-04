import pytest

from thor_devkit import rlp as m_rlp
from thor_devkit.exceptions import DeserializationError, SerializationError


def test_bytes_kind():
    kind = m_rlp.BytesKind()

    assert kind.serialize(bytes.fromhex("ff")) == b"\xff"
    assert kind.serialize(bytes.fromhex("01ff")) == b"\x01\xff"

    assert kind.deserialize(bytes.fromhex("ff")) == b"\xff"
    assert kind.deserialize(bytes.fromhex("01ff")) == b"\x01\xff"

    with pytest.raises(TypeError):
        kind.serialize(1)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        kind.serialize("0x1234")  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        kind.deserialize("01ff")  # type: ignore[arg-type]


def test_numeric_kind_encode():
    # Set up a max 8 bytes width NumericKind.
    kind = m_rlp.NumericKind(8)

    # Should pass
    assert kind.serialize("0x0").hex() == ""
    assert kind.serialize("0x123").hex() == "0123"
    assert kind.serialize("0").hex() == ""
    assert kind.serialize("100").hex() == "64"
    assert kind.serialize(0).hex() == ""
    assert kind.serialize(0x123).hex() == "0123"

    # Should Throw
    with pytest.raises(
        SerializationError, match="The input string does not represent a number"
    ):
        kind.serialize("0x123z")

    with pytest.raises(TypeError, match=r"expected str or int, got.+"):
        kind.serialize({})  # type: ignore[arg-type]

    with pytest.raises(
        SerializationError, match="The input string does not represent a number"
    ):
        kind.serialize("0x")

    with pytest.raises(SerializationError, match="Cannot serialize negative integers"):
        kind.serialize(-1)

    with pytest.raises(
        SerializationError, match=r"Integer too large \(does not fit in 8 bytes\)"
    ):
        kind.serialize("0x12345678123456780")

    with pytest.raises(TypeError, match=r"expected str or int, got.+"):
        kind.serialize(None)  # type: ignore[arg-type]

    # We won't hit this exception because big int are safe in Python.
    # Max Integer problem in Javascript: 2^53 -1
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/isSafeInteger
    # No such problem in Python:
    # https://stackoverflow.com/questions/7604966/maximum-and-minimum-values-for-ints
    #
    # with pytest.raises(SerializationError):
    #     kind.serialize(2 ** 64)


def test_numeric_kind_decode():
    # Set up a max 8 bytes width NumericKind.
    kind = m_rlp.NumericKind(8)

    # Should pass.
    assert kind.deserialize(bytes(0)) == 0
    assert kind.deserialize(bytes([1, 2, 3])) == int("0x010203", 16)
    assert kind.deserialize(bytes(range(1, 9))) == int("0x102030405060708", 16)

    # Should fail.
    with pytest.raises(DeserializationError, match=r".+wrong size.+"):
        kind.deserialize(bytes([1] * 9))

    with pytest.raises(DeserializationError, match=r".+leading zeroes"):
        kind.deserialize(bytes([0, 1, 2]))


def test_blob_kind_encode():
    kind = m_rlp.BlobKind()
    assert kind.serialize("0x1234567890").hex() == "1234567890"

    with pytest.raises(SerializationError, match=r".+even.+"):
        kind.serialize("0x1")

    with pytest.raises(SerializationError, match=r"Expected.+string"):
        kind.serialize("0xxy")

    with pytest.raises(TypeError, match=r'.+of type "str".+'):
        kind.serialize(1)  # type: ignore[arg-type]


def test_blob_kind_decode():
    kind = m_rlp.BlobKind()

    assert kind.deserialize(bytes([1, 2, 3, 4, 5])) == "0x0102030405"

    with pytest.raises(TypeError, match=r"expected bytes.+"):
        kind.deserialize("12")  # type: ignore[arg-type]


def test_fixed_blob_encode():
    kind = m_rlp.FixedBlobKind(4)

    assert kind.serialize("0x12345678").hex() == "12345678"

    with pytest.raises(SerializationError, match=r"Expected.+string"):
        kind.serialize("0x1234567z")

    with pytest.raises(SerializationError, match=r"Expected string of length 10"):
        kind.serialize("0x1234567890")

    with pytest.raises(SerializationError, match=r"Expected string of length 10"):
        kind.serialize("0x1234567")

    with pytest.raises(TypeError, match=r'.+of type "str".+'):
        kind.serialize(1)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match=r'.+of type "str".+'):
        kind.serialize(None)  # type: ignore[arg-type]


def test_fixed_blob_decode():
    kind = m_rlp.FixedBlobKind(4)

    assert kind.deserialize(bytes([1, 2, 3, 4])) == "0x01020304"

    with pytest.raises(DeserializationError, match=r"Bytes should be of length 4"):
        kind.deserialize(bytes([0, 0]))

    with pytest.raises(DeserializationError, match=r"Bytes should be of length 4"):
        kind.deserialize(bytes(0))


def test_optional_fixed_blob_kind_encode():
    kind = m_rlp.OptionalFixedBlobKind(4)

    assert kind.serialize(None).hex() == ""
    assert kind.serialize("0x12345678").hex() == "12345678"

    with pytest.raises(SerializationError, match=r"Expected.+string"):
        kind.serialize("0x1234567z")

    with pytest.raises(SerializationError, match=r"Expected string of length 10"):
        kind.serialize("0x11")

    with pytest.raises(SerializationError, match=r"Expected string of length 10"):
        kind.serialize("0x1234567890")

    with pytest.raises(SerializationError, match=r"Expected string of length 10"):
        kind.serialize("0x1234567")

    with pytest.raises(TypeError):
        kind.serialize(1)  # type: ignore[arg-type]

    with pytest.raises(SerializationError, match=r"Expected string of length 10"):
        kind.serialize("0x")


def test_optional_fixed_blob_kind_decode():
    kind = m_rlp.OptionalFixedBlobKind(4)

    assert kind.deserialize(bytes(0)) is None
    assert kind.deserialize(bytes([1, 2, 3, 4])) == "0x01020304"

    with pytest.raises(DeserializationError, match=r"Bytes should be of length 4"):
        kind.deserialize(bytes(2))


def test_compact_fixed_blobkind_encode():
    kind = m_rlp.CompactFixedBlobKind(4)
    # zero leading
    assert kind.serialize("0x00112233").hex() == "112233"
    # zero in the middle
    assert kind.serialize("0x11002233").hex() == "11002233"


def test_compact_fixed_blobkind_decode():
    kind = m_rlp.CompactFixedBlobKind(4)
    # Should prefix the zeros
    assert kind.deserialize(bytes([1])) == "0x00000001"
    # Should prefix the zeros, and the middle zeros should not interfere.
    assert kind.deserialize(bytes.fromhex("110022")) == "0x00110022"

    with pytest.raises(DeserializationError, match=r".+too long.+"):
        kind.deserialize(b"1122334455")

    with pytest.raises(DeserializationError, match=r".+no leading zeroes"):
        kind.deserialize(bytes(1))


def test_compact_fixed_blobkind_encode_with_zero():
    kind = m_rlp.CompactFixedBlobKind(4)
    assert kind.serialize("0x00000000") == b""
    assert kind.deserialize(b"") == "0x00000000"


@pytest.fixture()
def complex_data():
    return {
        "foo": 123,
        "bar": "0x12345678",
        "baz": [{"x": "0x11", "y": 1234}, {"x": "0x12", "y": 5678}],
    }


@pytest.fixture()
def complex_encoded():
    return "d17b8412345678cac4118204d2c41282162e"


@pytest.fixture()
def complex_codec():
    return m_rlp.ComplexCodec(
        m_rlp.DictWrapper(
            [
                ("foo", m_rlp.NumericKind()),
                ("bar", m_rlp.FixedBlobKind(4)),
                (
                    "baz",
                    m_rlp.ListWrapper(
                        [
                            m_rlp.DictWrapper(
                                [("x", m_rlp.BlobKind()), ("y", m_rlp.NumericKind())]
                            ),
                            m_rlp.DictWrapper(
                                [("x", m_rlp.BlobKind()), ("y", m_rlp.NumericKind())]
                            ),
                        ]
                    ),
                ),
            ]
        )
    )


@pytest.fixture()
def complex_codec_homo():
    return m_rlp.ComplexCodec(
        m_rlp.DictWrapper(
            {
                "foo": m_rlp.NumericKind(),
                "bar": m_rlp.FixedBlobKind(4),
                "baz": m_rlp.HomoListWrapper(
                    m_rlp.DictWrapper({"x": m_rlp.BlobKind(), "y": m_rlp.NumericKind()})
                ),
            }
        )
    )


@pytest.fixture()
def complex_data_nested():
    return {
        "foo": 123,
        "bar": "0x12345678",
        "baz": [
            {"x": "0x11", "y": 1234},
            {"x": "0x12", "y": 5678},
            789,
            [123, {"a": 1}],
        ],
    }


@pytest.fixture()
def complex_codec_nested():
    return m_rlp.ComplexCodec(
        m_rlp.DictWrapper(
            {
                "foo": m_rlp.NumericKind(),
                "bar": m_rlp.FixedBlobKind(4),
                "baz": m_rlp.ListWrapper(
                    [
                        m_rlp.DictWrapper(
                            {"x": m_rlp.BlobKind(), "y": m_rlp.NumericKind()}
                        ),
                        m_rlp.DictWrapper(
                            {"x": m_rlp.BlobKind(), "y": m_rlp.NumericKind()}
                        ),
                        m_rlp.NumericKind(),
                        m_rlp.ListWrapper(
                            [
                                m_rlp.NumericKind(),
                                m_rlp.DictWrapper({"a": m_rlp.NumericKind()}),
                            ]
                        ),
                    ]
                ),
            }
        )
    )


def test_rlp_complex(complex_data, complex_codec, complex_encoded):
    assert complex_codec.encode(complex_data).hex() == complex_encoded
    assert complex_codec.decode(bytes.fromhex(complex_encoded)) == complex_data


def test_rlp_complex_malformed_1(complex_data, complex_codec):
    complex_data.pop("foo")
    with pytest.raises(SerializationError, match=r"Keys count differs:.+"):
        complex_codec.encode(complex_data)


def test_rlp_complex_malformed_2(complex_data, complex_codec):
    complex_data.pop("foo")
    complex_data["sam"] = 19
    with pytest.raises(SerializationError, match=r"Missing key.+"):
        complex_codec.encode(complex_data)


def test_rlp_complex_malformed_3(complex_data, complex_codec):
    complex_data.pop("foo")
    complex_data["sam"] = 18
    complex_data["say"] = 19
    with pytest.raises(SerializationError, match=r"Keys count differs:.+"):
        complex_codec.encode(complex_data)


def test_rlp_complex_malformed_4(complex_data, complex_codec):
    complex_data["baz"].append(2)
    with pytest.raises(SerializationError, match=r"Items count differs:.+"):
        complex_codec.encode(complex_data)


def test_rlp_complex_malformed_5(complex_data, complex_codec):
    complex_data["baz"].pop(-1)
    with pytest.raises(SerializationError, match=r"Items count differs:.+"):
        complex_codec.encode(complex_data)


def test_rlp_complex_homo(complex_data, complex_codec_homo, complex_encoded):
    assert complex_codec_homo.encode(complex_data).hex() == complex_encoded
    assert complex_codec_homo.decode(bytes.fromhex(complex_encoded)) == complex_data


def test_rlp_complex_strange(complex_data_nested, complex_codec_nested):
    my_bytes = complex_codec_nested.encode(complex_data_nested)
    assert complex_codec_nested.decode(my_bytes) == complex_data_nested
