import pytest
from thor_devkit import abi
from thor_devkit import cry

f1 = abi.FUNCTION({
        "constant": False,
        "inputs": [
            {
                "name": "a1",
                "type": "uint256"
            },
            {
                "name": "a2",
                "type": "string"
            }
        ],
        "name": "f1",
        "outputs": [
            {
                "name": "r1",
                "type": "address"
            },
            {
                "name": "r2",
                "type": "bytes"
            }
        ],
        "payable": False,
        "stateMutability": "nonpayable",
        "type": "function"
})


f2 = abi.FUNCTION({
        "inputs": [],
        "name": "nodes",
        "payable": False,
        "outputs": [
            {
                "components": [
                    {
                        "internalType": "address",
                        "name": "master",
                        "type": "address"
                    },
                    {
                        "internalType": "address",
                        "name": "endorsor",
                        "type": "address"
                    },
                    {
                        "internalType": "bytes32",
                        "name": "identity",
                        "type": "bytes32"
                    },
                    {
                        "internalType": "bool",
                        "name": "active",
                        "type": "bool"
                    }
                ],
                "internalType": "struct AuthorityUtils.Candidate[]",
                "name": "list",
                "type": "tuple[]"
            }
        ],
        "stateMutability": "nonpayable",
        "type": "function"
    })

# Solidity
# function getStr() public pure returns (string memory) {
#     return "Hello World!";
# }

f3 = abi.FUNCTION({
    "inputs": [],
    "name": "getStr",
    "outputs": [
        {
            "internalType": "string",
            "name": "",
            "type": "string"
        }
    ],
    "stateMutability": "pure",
    "type": "function"
})

# Solidity
# function getBool() public pure returns (bool) {
#     return true;
# }
f4 = abi.FUNCTION(
	{
		"inputs": [],
		"name": "getBool",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "pure",
		"type": "function"
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
            {
                "internalType": "uint256",
                "name": "a",
                "type": "uint256"
            },
            {
                "internalType": "int256",
                "name": "b",
                "type": "int256"
            }
        ],
        "stateMutability": "pure",
        "type": "function"
    }
)


e1 = abi.EVENT({
    "anonymous": False,
    "inputs": [
        {
            "indexed": True,
            "name": "a1",
            "type": "uint256"
        },
        {
            "indexed": False,
            "name": "a2",
            "type": "string"
        }
    ],
    "name": "E1",
    "type": "event"
})


e2 = abi.EVENT({
    "anonymous": True,
    "inputs": [
        {
            "indexed": True,
            "name": "a1",
            "type": "uint256"
        },
        {
            "indexed": False,
            "name": "a2",
            "type": "string"
        }
    ],
    "name": "E2",
    "type": "event"
})


e3 = abi.EVENT({
    "anonymous": False,
    "inputs": [
        {
            "indexed": True,
            "name": "a1",
            "type": "uint256"
        }
    ],
    "name": "E3",
    "type": "event"
})


e4 = abi.EVENT({
    "inputs": [
        {
            "indexed": True,
            "name": "a1",
            "type": "string"
        }
    ],
    "name": "E4",
    "type": "event"
})

def test_coder():
    assert abi.Coder.encode_single(
        'uint256', 
        2345675643
    ).hex() == '000000000000000000000000000000000000000000000000000000008bd02b7b'
    
    with pytest.raises(Exception):
        abi.Coder.encode_single('bytes32', '0xdf3234')

    assert abi.Coder.encode_single(
        'bytes32',
        bytes.fromhex('df32340000000000000000000000000000000000000000000000000000000000')
    ).hex() == 'df32340000000000000000000000000000000000000000000000000000000000'

    assert abi.Coder.encode_list(
        ['bytes'], 
        [
            bytes.fromhex('df3234')
        ]
    ).hex() == '00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003df32340000000000000000000000000000000000000000000000000000000000'

    assert abi.Coder.encode_list(
        ['bytes32[]'],
        [
            [
                bytes.fromhex('df32340000000000000000000000000000000000000000000000000000000000'),
                bytes.fromhex('fdfd000000000000000000000000000000000000000000000000000000000000')
            ]
        ]
    ).hex() == '00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002df32340000000000000000000000000000000000000000000000000000000000fdfd000000000000000000000000000000000000000000000000000000000000'

    assert abi.Coder.decode_single(
        'uint256',
        bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000010')
    ) == 16

    assert abi.Coder.decode_single(
        'string',
        bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000848656c6c6f212521000000000000000000000000000000000000000000000000')
    ) == "Hello!%!"


def test_function():
    f = abi.Function(f1)
    assert f.selector.hex() == '27fcbb2f'
    assert f.get_selector().hex() == '27fcbb2f'
    assert f.get_name() == 'f1'

    assert f.encode([1, 'foo'], to_hex=True) == '0x27fcbb2f000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000003666f6f0000000000000000000000000000000000000000000000000000000000'

    expected = {
        "0": '0xabc0000000000000000000000000000000000001',
        "1": bytes.fromhex('666f6f'),
        "r1": '0xabc0000000000000000000000000000000000001',
        "r2": bytes.fromhex('666f6f')
    }
    assert expected == f.decode(bytes.fromhex('000000000000000000000000abc000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000003666f6f0000000000000000000000000000000000000000000000000000000000'))


def test_string():
    f = abi.Function(f3)
    assert f.selector.hex() == 'b8c9e4ed'
    assert f.get_selector().hex() == 'b8c9e4ed'
    assert f.get_name() == 'getStr'

    expected = {
        "0": "Hello World!"
    }
    assert expected == f.decode(bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c48656c6c6f20576f726c64210000000000000000000000000000000000000000'))


def test_bool():
    f = abi.Function(f4)
    assert f.selector.hex() == '12a7b914'
    assert f.get_selector().hex() == '12a7b914'
    assert f.get_name() == 'getBool'

    expected = {
        "0": True
    }

    assert expected == f.decode(bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001'))

def test_big_number():
    f = abi.Function(f5)
    assert f.selector.hex() == 'ff0d6c7d'
    assert f.get_selector().hex() == 'ff0d6c7d'
    assert f.get_name() == 'getBigNumbers'

    expected = {
        "0": 123456,
        "1": -123456,
        "a": 123456,
        "b": -123456
    }

    assert expected == f.decode(bytes.fromhex('000000000000000000000000000000000000000000000000000000000001e240fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe1dc0'))

# def test_abiv2():
#     f = abi.Function(f2)

#     output_hex = '000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000060000000000000000000000006935455ef590eb8746f5230981d09d3552398018000000000000000000000000b5358b034647202d0cd3d1bf615e63e498e0268249984a53f9397370079bba8d95f5c15c743098fb318483e0cb6bbf46ec89ccfb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000005ff66ee3a3ea2aba2857ea8276edb6190d9a1661000000000000000000000000d51666c6b4fed6070a78691f1f3c8e79ad02e3a076f090d383f49d8faab2eb151241528a552f0ae645f460360a7635b8883987a60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c5a02c1eac7516a9275d86c1cb39a5262b8684a4000000000000000000000000e32499b4143830f2526c79d388ecee530b6357aac635894a50ce5c74c62d238dbe95bd6a0fa076029d913d76b0d0b111c538153f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e8fd586e022f825a109848832d7e552132bc332000000000000000000000000224626926a7a12225a60e127cec119c939db4a5cdbf2712e19af00dc4d376728f7cb06cc215c8e7c53b94cb47cefb4a26ada2a6c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ea2e8c9d6dcad9e4be4f1c88a3befb8ea742832e0000000000000000000000001a011475baa1d368fa2d8328a1b7a8d848b62c94c68dc811199d40ff7ecd8c8d46454ad9ac5f5cde9bae32f927fec10d82dbdf7800000000000000000000000000000000000000000000000000000000000000000000000000000000000000004977d68df97bb313b23238520580d8d3a59939bf0000000000000000000000007ad1d568b3fe5bad3fc264aca70bc7bcd5e4a6ff83b137cf7e30864b8a4e56453eb1f094b4434685d86895de38ac2edcf5d3f5340000000000000000000000000000000000000000000000000000000000000000'

#     decoded = f.decode(bytes.fromhex(output_hex))


def test_event():
    e = abi.Event(e1)
    assert e.signature.hex() == '47b78f0ec63d97830ace2babb45e6271b15a678528e901a9651e45b65105e6c2'
    assert e.get_signature().hex() == '47b78f0ec63d97830ace2babb45e6271b15a678528e901a9651e45b65105e6c2'

    assert e.decode(
        bytes.fromhex('00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003666f6f0000000000000000000000000000000000000000000000000000000000'),
        [
            bytes.fromhex('47b78f0ec63d97830ace2babb45e6271b15a678528e901a9651e45b65105e6c2'),
            bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
        ]
    ) == { "0": 1, "1": "foo", "a1": 1, "a2": "foo" }

    assert e.encode({
        'a1': None,
    }) == [
        bytes.fromhex('47b78f0ec63d97830ace2babb45e6271b15a678528e901a9651e45b65105e6c2'),
        None
    ]

    assert e.encode({
        'a1': 1
    }) == [
        bytes.fromhex('47b78f0ec63d97830ace2babb45e6271b15a678528e901a9651e45b65105e6c2'),
        bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
    ]

    with pytest.raises(ValueError):
        assert e.encode({
            'a1': 1,
            'x': 3
        }) == [
            bytes.fromhex('47b78f0ec63d97830ace2babb45e6271b15a678528e901a9651e45b65105e6c2'),
            bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
        ]

    ee = abi.Event(e2)
    assert ee.decode(
        bytes.fromhex('00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003666f6f0000000000000000000000000000000000000000000000000000000000'),
        [
            bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
        ]
    ) == { "0": 1, "1": "foo", "a1": 1, "a2": "foo" }

    assert ee.encode({
        'a1': 1
    }) == [
        bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
    ]

    assert ee.encode([1]) == [
        bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
    ]

    eee = abi.Event(e3)
    assert eee.encode({
        'a1': 1
    }) == [
        bytes.fromhex('e96585649d926cc4f5031a6113d7494d766198c0ac68b04eb93207460f9d7fd2'),
        bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
    ]

    assert eee.decode(
        bytes.fromhex('00'),
        [
            bytes.fromhex('e96585649d926cc4f5031a6113d7494d766198c0ac68b04eb93207460f9d7fd2'),
            bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
        ]
    ) == { "0": 1, "a1": 1 }

    eeee = abi.Event(e4)
    assert eeee.encode({
        'a1': 'hello'
    }) == [
        eeee.signature,
        cry.keccak256(['hello'.encode('utf-8')])[0]
    ]