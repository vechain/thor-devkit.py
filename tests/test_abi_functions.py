from typing import Any

import pytest

from thor_devkit.abi import Function, FunctionT

# *********************** FIXTURES **************************


@pytest.fixture()
def simple_dynamic():
    data: FunctionT = {
        "inputs": [{"name": "a1", "type": "uint256"}, {"name": "a2", "type": "string"}],
        "name": "f1",
        "outputs": [{"name": "r1", "type": "address"}, {"name": "r2", "type": "bytes"}],
        "stateMutability": "nonpayable",
        "type": "function",
    }
    return Function(data)


@pytest.fixture()
def f_get_str():
    """
    function getStr() public pure returns (string memory) {
        return "Hello World!";
    }
    """
    data: FunctionT = {
        "inputs": [],
        "name": "getStr",
        "outputs": [{"internalType": "string", "name": "memory", "type": "string"}],
        "stateMutability": "pure",
        "type": "function",
    }
    return Function(data)


@pytest.fixture()
def f_get_bool():
    """
    function getBool() public pure returns (bool) {
        return true;
    }
    """
    data: FunctionT = {
        "inputs": [],
        "name": "getBool",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "pure",
        "type": "function",
    }
    return Function(data)


@pytest.fixture()
def f_get_big_numbers():
    """
    function getBigNumbers() public pure returns (uint256 a, int256 b) {
        return (123456, -123456);
    }
    """
    data: FunctionT = {
        "inputs": [],
        "name": "getBigNumbers",
        "outputs": [
            {"internalType": "uint256", "name": "a", "type": "uint256"},
            {"internalType": "int256", "name": "b", "type": "int256"},
        ],
        "stateMutability": "pure",
        "type": "function",
    }
    return Function(data)


@pytest.fixture()
def f_out_struct_dynarray():
    data: FunctionT = {
        "inputs": [],
        "name": "nodes",
        "outputs": [
            {
                "components": [
                    {"internalType": "address", "name": "master", "type": "address"},
                    {"internalType": "address", "name": "endorsor", "type": "address"},
                    {"internalType": "bytes32", "name": "identity", "type": "bytes32"},
                    {"internalType": "bool", "name": "active", "type": "bool"},
                ],
                "internalType": "struct AuthorityUtils.Candidate[]",
                "name": "list",
                "type": "tuple[]",
            }
        ],
        "stateMutability": "nonpayable",
        "type": "function",
    }
    return Function(data)


@pytest.fixture()
def f_out_struct_dynarray_data():
    return {
        "list": [
            {
                "master": "0x6935455ef590eb8746f5230981d09d3552398018",
                "endorsor": "0xb5358b034647202d0cd3d1bf615e63e498e02682",
                "identity": bytes.fromhex(
                    "49984a53f9397370079bba8d95f5c15c743098fb318483e0cb6bbf46ec89ccfb"
                ),
                "active": False,
            },
            {
                "master": "0x5ff66ee3a3ea2aba2857ea8276edb6190d9a1661",
                "endorsor": "0xd51666c6b4fed6070a78691f1f3c8e79ad02e3a0",
                "identity": bytes.fromhex(
                    "76f090d383f49d8faab2eb151241528a552f0ae645f460360a7635b8883987a6"
                ),
                "active": False,
            },
            {
                "master": "0xc5a02c1eac7516a9275d86c1cb39a5262b8684a4",
                "endorsor": "0xe32499b4143830f2526c79d388ecee530b6357aa",
                "identity": bytes.fromhex(
                    "c635894a50ce5c74c62d238dbe95bd6a0fa076029d913d76b0d0b111c538153f"
                ),
                "active": False,
            },
            {
                "master": "0x0e8fd586e022f825a109848832d7e552132bc332",
                "endorsor": "0x224626926a7a12225a60e127cec119c939db4a5c",
                "identity": bytes.fromhex(
                    "dbf2712e19af00dc4d376728f7cb06cc215c8e7c53b94cb47cefb4a26ada2a6c"
                ),
                "active": False,
            },
            {
                "master": "0xea2e8c9d6dcad9e4be4f1c88a3befb8ea742832e",
                "endorsor": "0x1a011475baa1d368fa2d8328a1b7a8d848b62c94",
                "identity": bytes.fromhex(
                    "c68dc811199d40ff7ecd8c8d46454ad9ac5f5cde9bae32f927fec10d82dbdf78"
                ),
                "active": False,
            },
            {
                "master": "0x4977d68df97bb313b23238520580d8d3a59939bf",
                "endorsor": "0x7ad1d568b3fe5bad3fc264aca70bc7bcd5e4a6ff",
                "identity": bytes.fromhex(
                    "83b137cf7e30864b8a4e56453eb1f094b4434685d86895de38ac2edcf5d3f534"
                ),
                "active": False,
            },
        ]
    }


@pytest.fixture()
def f_out_struct_dynarray_enc(f_out_struct_dynarray_data):
    items = f_out_struct_dynarray_data["list"]
    return bytes.fromhex(
        "".join(
            [
                "20".rjust(64, "0"),  # address of value
                hex(len(items))[2:].rjust(64, "0"),  # length
            ]
            + [
                "".join(
                    [
                        d["master"][2:].rjust(64, "0"),
                        d["endorsor"][2:].rjust(64, "0"),
                        d["identity"].hex(),
                        str(int(d["active"])).rjust(64, "0"),
                    ]
                )
                for d in items
            ]
        )
    )


@pytest.fixture()
def f_in_struct():
    data: FunctionT = {
        "inputs": [
            {
                "components": [
                    {"internalType": "bool", "name": "flag1", "type": "bool"},
                    {"internalType": "bool", "name": "flag2", "type": "bool"},
                    {"internalType": "address", "name": "identity", "type": "address"},
                ],
                "internalType": "struct ThisClass.SomeStruct",
                "name": "args",
                "type": "tuple",
            }
        ],
        "name": "doSomething",
        "outputs": [],
        "stateMutability": "pure",
        "type": "function",
    }
    return Function(data)


@pytest.fixture()
def f_in_struct_data():
    return {
        "args": {
            "flag1": True,
            "flag2": True,
            "identity": "0x4977d68df97bb313b23238520580d8d3a59939bf",
        }
    }


@pytest.fixture()
def f_in_struct_enc(f_in_struct_data):
    bool1, bool2, b = f_in_struct_data["args"].values()
    return bytes.fromhex(
        str(int(bool1)).rjust(64, "0")
        + str(int(bool2)).rjust(64, "0")
        + b[2:].rjust(64, "0")
    )


def _make_f_in_struct_dynarray(array_size=""):
    data: FunctionT = {
        "inputs": [
            {
                "components": [
                    {"internalType": "bool", "name": "flag1", "type": "bool"},
                    {"internalType": "bool", "name": "flag2", "type": "bool"},
                    {"internalType": "address", "name": "identity", "type": "address"},
                ],
                "internalType": f"struct ThisClass.SomeStruct[{array_size}]",
                "name": "args",
                "type": f"tuple[{array_size}]",
            }
        ],
        "name": "doSomething",
        "outputs": [],
        "stateMutability": "pure",
        "type": "function",
    }
    return Function(data)


@pytest.fixture()
def f_in_struct_dynarray():
    return _make_f_in_struct_dynarray("")


@pytest.fixture(params=[1, 2, 4, 17])
def f_in_struct_dynarray_data(f_in_struct_data, request):
    return {"args": [f_in_struct_data["args"] for _ in range(request.param)]}


@pytest.fixture()
def f_in_struct_dynarray_enc(f_in_struct_dynarray_data, dyn_prefix):
    return bytes.fromhex(
        dyn_prefix.hex()
        + hex(len(f_in_struct_dynarray_data["args"]))[2:].rjust(64, "0")
        + "".join(
            [
                (
                    str(int(d["flag1"])).rjust(64, "0")
                    + str(int(d["flag2"])).rjust(64, "0")
                    + d["identity"][2:].rjust(64, "0")
                )
                for d in f_in_struct_dynarray_data["args"]
            ]
        )
    )


@pytest.fixture(params=[1, 2, 4, 17])
def f_in_struct_fixarray_data(f_in_struct_data, request):
    return {"args": [f_in_struct_data["args"] for _ in range(request.param)]}


@pytest.fixture()
def f_in_struct_fixarray(f_in_struct_fixarray_data):
    return _make_f_in_struct_dynarray(len(f_in_struct_fixarray_data["args"]))


@pytest.fixture()
def f_in_struct_fixarray_enc(f_in_struct_fixarray_data):
    return bytes.fromhex(
        "".join(
            [
                (
                    str(int(d["flag1"])).rjust(64, "0")
                    + str(int(d["flag2"])).rjust(64, "0")
                    + d["identity"][2:].rjust(64, "0")
                )
                for d in f_in_struct_fixarray_data["args"]
            ]
        )
    )


@pytest.fixture(params=[1, 2, 4, 17])
def f_in_struct_complex_data(f_in_struct_data, request):
    return {
        "args": [f_in_struct_data["args"] for _ in range(request.param)],
        "args2": [f_in_struct_data["args"] for _ in range(request.param + 2)],
        "flag0": True,
    }


@pytest.fixture()
def f_in_struct_complex(f_in_struct_complex_data):
    array_size = len(f_in_struct_complex_data["args"])
    data: FunctionT = {
        "inputs": [
            {
                "components": [
                    {"internalType": "bool", "name": "flag1", "type": "bool"},
                    {"internalType": "bool", "name": "flag2", "type": "bool"},
                    {"internalType": "address", "name": "identity", "type": "address"},
                ],
                "internalType": f"struct ThisClass.SomeStruct[{array_size}]",
                "name": "args",
                "type": "tuple[]",
            },
            {
                "components": [
                    {"internalType": "bool", "name": "flag1", "type": "bool"},
                    {"internalType": "bool", "name": "flag2", "type": "bool"},
                    {"internalType": "address", "name": "identity", "type": "address"},
                ],
                "internalType": f"struct ThisClass.SomeStruct[{array_size + 2}]",
                "name": "args2",
                "type": "tuple[]",
            },
            {
                "internalType": "bool",
                "name": "flag0",
                "type": "bool",
            },
        ],
        "name": "doSomething",
        "outputs": [],
        "stateMutability": "pure",
        "type": "function",
    }
    return Function(data)


@pytest.fixture()
def f_in_struct_complex_enc(f_in_struct_complex_data, dyn_prefix):
    array_size = len(f_in_struct_complex_data["args"])
    return bytes.fromhex(
        hex(32 * 3)[2:].rjust(64, "0")
        + hex(32 * 4 + array_size * 32 * 3)[2:].rjust(64, "0")
        + hex(int(f_in_struct_complex_data["flag0"]))[2:].rjust(64, "0")
        + hex(array_size)[2:].rjust(64, "0")
        + "".join(
            [
                (
                    str(int(d["flag1"])).rjust(64, "0")
                    + str(int(d["flag2"])).rjust(64, "0")
                    + d["identity"][2:].rjust(64, "0")
                )
                for d in f_in_struct_complex_data["args"]
            ]
        )
        + hex(array_size + 2)[2:].rjust(64, "0")
        + "".join(
            [
                (
                    str(int(d["flag1"])).rjust(64, "0")
                    + str(int(d["flag2"])).rjust(64, "0")
                    + d["identity"][2:].rjust(64, "0")
                )
                for d in f_in_struct_complex_data["args2"]
            ]
        )
    )


# ***********************************************************


def test_function(simple_dynamic: Function):
    selector = "27fcbb2f"
    assert simple_dynamic.selector.hex() == selector
    assert simple_dynamic.name == "f1"

    encoded = bytes.fromhex(
        selector
        + "1".rjust(64, "0")  # True
        + "40".rjust(64, "0")  # address of 2nd argument ("foo")
        + hex(len(b"foo"))[2:].rjust(64, "0")  # len("foo")
        + b"foo".hex().ljust(64, "0")  # "foo"
    )
    assert simple_dynamic.encode([1, "foo"]).hex() == encoded.hex()
    assert simple_dynamic.encode({"a1": 1, "a2": "foo"}).hex() == encoded.hex()
    assert simple_dynamic.decode_parameters(encoded).to_dict() == {"a1": 1, "a2": "foo"}

    expected: Any = {
        "r1": "0xabc0000000000000000000000000000000000001",
        "r2": b"foo",
    }
    encoded_out = bytes.fromhex(
        expected["r1"][2:].rjust(64, "0")
        + "40".rjust(64, "0")  # addr
        + hex(len(expected["r2"]))[2:].rjust(64, "0")
        + expected["r2"].hex().ljust(64, "0")
    )
    assert simple_dynamic.decode(encoded_out).to_dict() == expected
    assert simple_dynamic.encode_outputs(expected).hex() == encoded_out.hex()
    assert (
        simple_dynamic.encode_outputs(tuple(expected.values())).hex()
        == encoded_out.hex()
    )

    with pytest.warns(DeprecationWarning):
        simple_dynamic.encode([1, "foo"], to_hex=True)


def test_string(f_get_str: Function):
    assert f_get_str.selector.hex() == "b8c9e4ed"
    assert f_get_str.name == "getStr"

    memory = b"Hello World!"
    expected = {"memory": memory.decode()}
    encoded_out = bytes.fromhex(
        "20".rjust(64, "0")  # address
        + hex(len(memory))[2:].rjust(64, "0")  # length
        + memory.hex().ljust(64, "0")  # content
    )
    assert f_get_str.decode(encoded_out).to_dict() == expected
    assert f_get_str.encode_outputs(expected).hex() == encoded_out.hex()


def test_bool(f_get_bool: Function):
    assert f_get_bool.selector.hex() == "12a7b914"
    assert f_get_bool.name == "getBool"

    expected = {"ret_0": True}
    encoded_out = bytes.fromhex("1".rjust(64, "0"))
    result = f_get_bool.decode(encoded_out)

    assert result.to_dict() == expected
    assert result.ret_0 == expected["ret_0"]
    assert result == tuple(expected.values())

    assert f_get_bool.encode_outputs([True]).hex() == encoded_out.hex()

    with pytest.raises(ValueError, match=r".+unnamed.*"):
        f_get_bool.encode_outputs(expected)


def test_big_number(f_get_big_numbers: Function):
    assert f_get_big_numbers.selector.hex() == "ff0d6c7d"
    assert f_get_big_numbers.name == "getBigNumbers"

    expected = {"a": 123456, "b": -123456}
    encoded_out = bytes.fromhex(
        hex(expected["a"])[2:].rjust(64, "0")
        + hex(expected["b"] % 2**256)[2:].rjust(64, "0")
    )

    assert f_get_big_numbers.decode(encoded_out).to_dict() == expected
    assert f_get_big_numbers.encode_outputs(expected).hex() == encoded_out.hex()


def test_abiv2(
    f_out_struct_dynarray: Function,
    f_out_struct_dynarray_data,
    f_out_struct_dynarray_enc: bytes,
):
    assert (
        f_out_struct_dynarray.decode(f_out_struct_dynarray_enc).to_dict()
        == f_out_struct_dynarray_data
    )
    assert (
        f_out_struct_dynarray.encode_outputs(f_out_struct_dynarray_data).hex()
        == f_out_struct_dynarray_enc.hex()
    )


def test_inputs_struct(f_in_struct: Function, f_in_struct_data, f_in_struct_enc: bytes):
    selector = bytes.fromhex("3ca45dbf")
    encoded = selector + f_in_struct_enc
    assert f_in_struct.selector.hex() == selector.hex()
    assert f_in_struct.encode(f_in_struct_data).hex() == encoded.hex()
    assert (
        f_in_struct.encode([tuple(f_in_struct_data["args"].values())]).hex()
        == encoded.hex()
    )
    assert (
        f_in_struct.decode_parameters(selector + f_in_struct_enc).to_dict()
        == f_in_struct_data
    )


def test_inputs_struct_dynarray(
    f_in_struct_dynarray: Function,
    f_in_struct_dynarray_data,
    f_in_struct_dynarray_enc: bytes,
):
    selector = bytes.fromhex("eaf67dba")
    assert f_in_struct_dynarray.selector.hex() == selector.hex()
    assert (
        f_in_struct_dynarray.encode(f_in_struct_dynarray_data).hex()
        == selector.hex() + f_in_struct_dynarray_enc.hex()
    )
    assert (
        f_in_struct_dynarray.decode_parameters(
            selector + f_in_struct_dynarray_enc
        ).to_dict()
        == f_in_struct_dynarray_data
    )


def test_inputs_struct_fixarray(
    f_in_struct_fixarray: Function,
    f_in_struct_fixarray_data,
    f_in_struct_fixarray_enc: bytes,
):
    encoded = f_in_struct_fixarray.selector + f_in_struct_fixarray_enc
    assert f_in_struct_fixarray.encode(f_in_struct_fixarray_data).hex() == encoded.hex()
    assert (
        f_in_struct_fixarray.decode_parameters(encoded).to_dict()
        == f_in_struct_fixarray_data
    )


def test_inputs_complex(
    f_in_struct_complex: Function,
    f_in_struct_complex_data,
    f_in_struct_complex_enc: bytes,
):
    encoded = f_in_struct_complex.selector + f_in_struct_complex_enc
    assert f_in_struct_complex.encode(f_in_struct_complex_data).hex() == encoded.hex()
    assert (
        f_in_struct_complex.decode_parameters(encoded).to_dict()
        == f_in_struct_complex_data
    )
