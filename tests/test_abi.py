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

    assert f.encode([1, 'foo'], to_hex=True) == '0x27fcbb2f000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000003666f6f0000000000000000000000000000000000000000000000000000000000'

    expected = {
        "0": '0xabc0000000000000000000000000000000000001',
        "1": bytes.fromhex('666f6f'),
        "r1": '0xabc0000000000000000000000000000000000001',
        "r2": bytes.fromhex('666f6f')
    }
    assert expected == f.decode(bytes.fromhex('000000000000000000000000abc000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000003666f6f0000000000000000000000000000000000000000000000000000000000'))

def test_event():
    e = abi.Event(e1)
    assert e.signature.hex() == '47b78f0ec63d97830ace2babb45e6271b15a678528e901a9651e45b65105e6c2'

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
    assert eeee.encode({ 'a1': 'hello' }) == [ eeee.signature, '0x'+cry.keccak256(['hello'.encode('utf-8')])[0].hex() ]