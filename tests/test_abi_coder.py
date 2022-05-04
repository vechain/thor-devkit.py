import pytest
from eth_abi.exceptions import EncodingTypeError

from thor_devkit import abi

BYTES = ["df3234", "aa0033", "123450", "02aaaa", "00aaaa", "aaaa00"]


@pytest.fixture(params=BYTES)
def bytes_3(request):
    return bytes.fromhex(request.param)


@pytest.fixture()
def bytes_32(bytes_3):
    return bytes.fromhex(bytes_3.hex().ljust(64, "0"))


@pytest.fixture(params=BYTES)
def bytes_3_2(request):
    return bytes.fromhex(request.param)


@pytest.fixture()
def bytes_32_2(bytes_3_2):
    return bytes.fromhex(bytes_3_2.hex().ljust(64, "0"))


@pytest.fixture(params=[0, 1, 2, 2345675643, 2**256 - 1])
def int_256(request):
    return request.param


@pytest.fixture()
def int_256_enc(int_256):
    return bytes.fromhex(hex(int_256)[2:].rjust(64, "0"))


# Note that "\u0404" (euro sign AFAIR) is 2 bytes long. We *must* support unicode,
# so this edge-case is important
@pytest.fixture(params=["", "foo", "Hello, beautiful world!", "\u0404"])
def string(request):
    return request.param


@pytest.fixture()
def string_enc(string):
    enc = string.encode()
    return bytes.fromhex(hex(len(enc))[2:].rjust(64, "0") + enc.hex().ljust(64, "0"))


@pytest.fixture()
def bytes_32_array(bytes_32, bytes_32_2):
    return [bytes_32, bytes_32_2]


@pytest.fixture()
def bytes_32_dynarray_enc(bytes_32_array, dyn_prefix):
    return b"".join(
        [
            dyn_prefix,
            bytes.fromhex(hex(len(bytes_32_array))[2:].rjust(64, "0")),
            *bytes_32_array,
        ]
    )


def test_bytes_fixed_coder(bytes_3, bytes_32, dyn_prefix):
    with pytest.raises(EncodingTypeError):
        abi.Coder.encode_single("bytes32", "0x" + bytes_3.hex())

    assert abi.Coder.encode_single("bytes32", bytes_32).hex() == bytes_32.hex()
    assert abi.Coder.decode_single("bytes32", bytes_32).hex() == bytes_32.hex()


def test_bytes_dynamic_coder(bytes_3, dyn_prefix):
    assert (
        # Without exact length it's ok
        abi.Coder.encode_list(["bytes"], [bytes_3]).hex()
        == dyn_prefix.hex() + "3".rjust(64, "0") + bytes_3.hex().ljust(64, "0")
    )


def test_bytes_dynarray_coder(bytes_32_array, bytes_32_dynarray_enc):
    assert (
        abi.Coder.encode_list(["bytes32[]"], [bytes_32_array]).hex()
        == bytes_32_dynarray_enc.hex()
    )
    assert (
        abi.Coder.encode_single("bytes32[]", bytes_32_array).hex()
        == bytes_32_dynarray_enc.hex()
    )

    # Arrays are decoded as tuples
    assert abi.Coder.decode_list(["bytes32[]"], bytes_32_dynarray_enc) == [
        tuple(bytes_32_array)
    ]
    assert abi.Coder.decode_single("bytes32[]", bytes_32_dynarray_enc) == tuple(
        bytes_32_array
    )


def test_bytes_fixarray_coder(bytes_32_array):
    assert (
        abi.Coder.encode_list(["bytes32[2]"], [bytes_32_array]).hex()
        == b"".join(bytes_32_array).hex()
    )
    assert (
        abi.Coder.encode_single("bytes32[2]", bytes_32_array).hex()
        == b"".join(bytes_32_array).hex()
    )

    # Arrays are decoded as tuples
    assert abi.Coder.decode_list(["bytes32[2]"], b"".join(bytes_32_array)) == [
        tuple(bytes_32_array)
    ]
    assert abi.Coder.decode_single("bytes32[2]", b"".join(bytes_32_array)) == (
        tuple(bytes_32_array)
    )


def test_int_coder(int_256, int_256_enc):
    assert abi.Coder.encode_list(["uint256"], [int_256]).hex() == int_256_enc.hex()
    assert abi.Coder.encode_single("uint256", int_256).hex() == int_256_enc.hex()

    assert abi.Coder.decode_list(["uint256"], int_256_enc) == [int_256]
    assert abi.Coder.decode_single("uint256", int_256_enc) == int_256


def test_string_coder(string, string_enc, dyn_prefix):
    assert (
        abi.Coder.encode_single("string", string).hex()
        == dyn_prefix.hex() + string_enc.hex()
    )
    assert abi.Coder.decode_single("string", dyn_prefix + string_enc) == string

    assert (
        abi.Coder.encode_list(["string"], [string]).hex()
        == dyn_prefix.hex() + string_enc.hex()
    )
    assert abi.Coder.decode_list(["string"], dyn_prefix + string_enc) == [string]
