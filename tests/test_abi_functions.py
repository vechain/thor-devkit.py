import pytest

from thor_devkit import abi

# *********************** FIXTURES **************************


f1 = abi.FUNCTION(
    {
        "inputs": [{"name": "a1", "type": "uint256"}, {"name": "a2", "type": "string"}],
        "name": "f1",
        "outputs": [{"name": "r1", "type": "address"}, {"name": "r2", "type": "bytes"}],
        "stateMutability": "nonpayable",
        "type": "function",
    }
)


f2 = abi.FUNCTION(
    {
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
)

# Solidity
# function getStr() public pure returns (string memory) {
#     return "Hello World!";
# }

f3 = abi.FUNCTION(
    {
        "inputs": [],
        "name": "getStr",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "pure",
        "type": "function",
    }
)

# Solidity
# function getBool() public pure returns (bool) {
#     return true;
# }
f4 = abi.FUNCTION(
    {
        "inputs": [],
        "name": "getBool",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "pure",
        "type": "function",
    }
)

# function getBigNumbers() public pure returns (uint256 a, int256 b) {
#     return (123456, -123456);
# }
f5 = abi.FUNCTION(
    {
        "inputs": [],
        "name": "getBigNumbers",
        "outputs": [
            {"internalType": "uint256", "name": "a", "type": "uint256"},
            {"internalType": "int256", "name": "b", "type": "int256"},
        ],
        "stateMutability": "pure",
        "type": "function",
    }
)


f6 = abi.FUNCTION(
    {
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
                "internalType": "struct AuthorityUtils.Candidate",
                "name": "list",
                "type": "tuple",
            }
        ],
        "stateMutability": "nonpayable",
        "type": "function",
    }
)

f7 = abi.FUNCTION(
    {
        "inputs": [
            {
                "components": [
                    {"internalType": "bool", "name": "flag1", "type": "bool"},
                    {"internalType": "bool", "name": "flag2", "type": "bool"},
                    {"internalType": "address", "name": "identity", "type": "address"},
                ],
                "internalType": "struct ThisClass.SomeStruct[]",
                "name": "inputs",
                "type": "tuple[]",
            }
        ],
        "name": "doSomething",
        "outputs": [],
        "stateMutability": "pure",
        "type": "function",
    }
)

f8 = abi.FUNCTION(
    {
        "inputs": [
            {
                "components": [
                    {"internalType": "bool", "name": "flag1", "type": "bool"},
                    {"internalType": "bool", "name": "flag2", "type": "bool"},
                    {"internalType": "address", "name": "identity", "type": "address"},
                ],
                "internalType": "struct ThisClass.SomeStruct",
                "name": "inputs",
                "type": "tuple",
            }
        ],
        "name": "doSomething",
        "outputs": [],
        "stateMutability": "pure",
        "type": "function",
    }
)

# ***********************************************************


def test_coder():
    assert abi.Coder.encode_single("uint256", 2345675643).hex() == "0" * 56 + "8bd02b7b"

    with pytest.raises(Exception):
        abi.Coder.encode_single("bytes32", "0xdf3234")

    assert (
        abi.Coder.encode_single(
            "bytes32",
            bytes.fromhex("df3234" + "0" * 58),
        ).hex()
        == "df3234" + "0" * 58
    )

    assert (
        abi.Coder.encode_list(["bytes"], [bytes.fromhex("df3234")]).hex()
        == "0" * 62 + "2" + "0" * 64 + "3df3234" + "0" * 58
    )

    assert (
        abi.Coder.encode_list(
            ["bytes32[]"],
            [
                [
                    bytes.fromhex("df3234" + "0" * 58),
                    bytes.fromhex("fdfd" + "0" * 60),
                ]
            ],
        ).hex()
        == "0" * 62 + "2" + "0" * 64 + "2df3234" + "0" * 58 + "fdfd" + "0" * 60
    )

    assert (
        abi.Coder.decode_single(
            "uint256",
            bytes.fromhex("0" * 62 + "10"),
        )
        == 16
    )

    assert (
        abi.Coder.decode_single(
            "string",
            bytes.fromhex("0" * 62 + "2" + "0" * 64 + "848656c6c6f212521" + "0" * 48),
        )
        == "Hello!%!"
    )


def test_function():
    f = abi.Function(f1)
    assert f.selector.hex() == "27fcbb2f"
    assert f.name == "f1"

    assert (
        f.encode([1, "foo"], to_hex=True)
        == "0x27fcbb2f"
        + "0" * 63
        + "1"
        + "0" * 62
        + "4"
        + "0" * 64
        + "3666f6f"
        + "0" * 58
    )

    expected = {
        "r1": "0xabc0000000000000000000000000000000000001",
        "r2": bytes.fromhex("666f6f"),
    }
    assert (
        f.decode(
            bytes.fromhex(
                "0" * 24
                + "abc"
                + "0" * 36
                + "1"
                + "0" * 62
                + "4"
                + "0" * 64
                + "3666f6f"
                + "0" * 58
            )
        ).to_dict()
        == expected
    )


def test_string():
    f = abi.Function(f3)
    assert f.selector.hex() == "b8c9e4ed"
    assert f.name == "getStr"

    expected = {"ret_0": "Hello World!"}
    assert (
        f.decode(
            bytes.fromhex(
                "0" * 62 + "2" + "0" * 64 + "c48656c6c6f20576f726c6421" + "0" * 40
            )
        ).to_dict()
        == expected
    )


def test_bool():
    f = abi.Function(f4)
    assert f.selector.hex() == "12a7b914"
    assert f.name == "getBool"

    expected = {"ret_0": True}

    assert f.decode(bytes.fromhex("0" * 63 + "1")).to_dict() == expected


def test_big_number():
    f = abi.Function(f5)
    assert f.selector.hex() == "ff0d6c7d"
    assert f.name == "getBigNumbers"

    expected = {"a": 123456, "b": -123456}

    assert (
        expected
        == f.decode(bytes.fromhex("0" * 59 + "1e240" + "f" * 59 + "e1dc0")).to_dict()
    )


def test_abiv2():
    f = abi.Function(f2)

    data = {
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
    output_hex = (
        "0" * 62
        + "2"
        + "0" * 64
        + "6"
        + "0" * 24
        + "6935455ef590eb8746f5230981d09d3552398018"
        + "0" * 24
        + (
            "b5358b034647202d0cd3d1bf615e63e498e0268249984a53f9397370079bba8d"
            "95f5c15c743098fb318483e0cb6bbf46ec89ccfb"
        )
        + "0" * 88
        + "5ff66ee3a3ea2aba2857ea8276edb6190d9a1661"
        + "0" * 24
        + (
            "d51666c6b4fed6070a78691f1f3c8e79ad02e3a076f090d383f49d8faab2eb15"
            "1241528a552f0ae645f460360a7635b8883987a6"
        )
        + "0" * 88
        + "c5a02c1eac7516a9275d86c1cb39a5262b8684a4"
        + "0" * 24
        + (
            "e32499b4143830f2526c79d388ecee530b6357aac635894a50ce5c74c62d238d"
            "be95bd6a0fa076029d913d76b0d0b111c538153f"
        )
        + "0" * 89
        + "e8fd586e022f825a109848832d7e552132bc332"
        + "0" * 24
        + (
            "224626926a7a12225a60e127cec119c939db4a5cdbf2712e19af00dc4d376728"
            "f7cb06cc215c8e7c53b94cb47cefb4a26ada2a6c"
        )
        + "0" * 88
        + "ea2e8c9d6dcad9e4be4f1c88a3befb8ea742832e"
        + "0" * 24
        + (
            "1a011475baa1d368fa2d8328a1b7a8d848b62c94c68dc811199d40ff7ecd8c8d"
            "46454ad9ac5f5cde9bae32f927fec10d82dbdf78"
        )
        + "0" * 88
        + "4977d68df97bb313b23238520580d8d3a59939bf"
        + "0" * 24
        + (
            "7ad1d568b3fe5bad3fc264aca70bc7bcd5e4a6ff83b137cf7e30864b8a4e5645"
            "3eb1f094b4434685d86895de38ac2edcf5d3f534"
        )
        + "0" * 64
    )
    assert f.decode(bytes.fromhex(output_hex)).to_dict() == data


def test_abiv2_inputs():
    f = abi.Function(f8)

    result = f.encode(
        [
            (True, True, "0x4977d68df97bb313b23238520580d8d3a59939bf"),
        ]
    )
    assert result == bytes.fromhex(
        "3ca45dbf"
        + "0" * 63
        + "1"
        + "0" * 63
        + "1"
        + "0" * 24
        + "4977d68df97bb313b23238520580d8d3a59939bf"
    )


def test_abiv2_inputs_arr():
    f = abi.Function(f7)

    result = f.encode(
        [
            ((True, True, "0x4977d68df97bb313b23238520580d8d3a59939bf"),),
        ]
    )
    assert result == bytes.fromhex(
        "eaf67dba"
        + "0" * 62
        + "2"
        + "0" * 64
        + "1"
        + "0" * 63
        + "1"
        + "0" * 63
        + "1"
        + "0" * 24
        + "4977d68df97bb313b23238520580d8d3a59939bf"
    )
