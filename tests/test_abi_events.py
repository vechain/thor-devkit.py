import os
from tempfile import mkstemp

import pytest
from solcx.exceptions import SolcError

from thor_devkit import cry
from thor_devkit.abi import EVENT, Coder, Event


# *********************** FIXTURES **************************
@pytest.fixture()
def simple_event_no_hash():
    return EVENT(
        {
            "anonymous": False,
            "inputs": [
                {"indexed": True, "name": "a1", "type": "uint256"},
                {"indexed": False, "name": "a2", "type": "string"},
            ],
            "name": "E1",
            "type": "event",
        }
    )


@pytest.fixture()
def anonymous_event_no_hash():
    return EVENT(
        {
            "anonymous": True,
            "inputs": [
                {
                    "indexed": True,
                    "name": "a1",
                    "type": "uint256",
                    "internalType": "uint256",
                },
                {
                    "indexed": False,
                    "name": "a2",
                    "type": "string",
                    "internalType": "string",
                },
            ],
            "name": "E2",
            "type": "event",
        }
    )


@pytest.fixture()
def simple_event_hash():
    return EVENT(
        {
            "inputs": [{"indexed": True, "name": "a1", "type": "string"}],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def simple_event_int():
    return EVENT(
        {
            "anonymous": False,
            "inputs": [{"indexed": True, "name": "a1", "type": "uint256"}],
            "name": "E3",
            "type": "event",
        }
    )


@pytest.fixture()
def tuple_event():
    return EVENT(
        {
            "inputs": [
                {
                    "indexed": True,
                    "name": "a1",
                    "type": "tuple",
                    "components": [
                        {"name": "b1", "type": "string"},
                        {"name": "b2", "type": "string"},
                        {"name": "b3", "type": "uint8"},
                    ],
                },
                {"indexed": True, "name": "a2", "type": "bytes"},
                {"indexed": False, "name": "a3", "type": "bool"},
            ],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def tuple_fixed_array_event():
    return EVENT(
        {
            "inputs": [
                {
                    "indexed": True,
                    "name": "a1",
                    "type": "tuple[3]",
                    "components": [
                        {"name": "b1", "type": "string"},
                        {"name": "b2", "type": "string"},
                        {"name": "b3", "type": "uint8"},
                    ],
                },
                {"indexed": True, "name": "a2", "type": "string"},
                {"indexed": False, "name": "a3", "type": "bool"},
            ],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def tuple_dynamic_array_event():
    return EVENT(
        {
            "inputs": [
                {
                    "indexed": True,
                    "name": "a1",
                    "type": "tuple[]",
                    "components": [
                        {"name": "b1", "type": "string"},
                        {"name": "b2", "type": "string"},
                        {"name": "b3", "type": "uint8"},
                    ],
                },
                {"indexed": True, "name": "a2", "type": "string"},
                {"indexed": False, "name": "a3", "type": "bool"},
            ],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def fixed_array_event():
    return EVENT(
        {
            "inputs": [
                {"indexed": True, "name": "a1", "type": "int16[3]"},
            ],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def dynamic_array_event():
    return EVENT(
        {
            "inputs": [
                {"indexed": True, "name": "a1", "type": "int16[]"},
            ],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def unindexed_struct_event():
    return EVENT(
        {
            "inputs": [
                {
                    "indexed": False,
                    "name": "a1",
                    "type": "tuple",
                    "components": [
                        {"name": "b1", "type": "bool"},
                        {"name": "b2", "type": "string"},
                    ],
                },
            ],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def unindexed_struct_fixed_array_event():
    return EVENT(
        {
            "inputs": [
                {
                    "indexed": False,
                    "name": "a1",
                    "type": "tuple[3]",
                    "components": [
                        {"name": "b1", "type": "bool"},
                        {"name": "b2", "type": "string"},
                    ],
                },
            ],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def unindexed_struct_dynamic_array_event():
    return EVENT(
        {
            "inputs": [
                {
                    "indexed": False,
                    "name": "a1",
                    "type": "tuple[]",
                    "components": [
                        {"name": "b1", "type": "bool"},
                        {"name": "b2", "type": "string"},
                    ],
                },
            ],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def unindexed_struct_nested_event():
    return EVENT(
        {
            "inputs": [
                {
                    "indexed": False,
                    "name": "a1",
                    "type": "tuple[]",
                    "components": [
                        {
                            "name": "b1",
                            "type": "tuple",
                            "components": [
                                {"name": "c1", "type": "bool"},
                                {"name": "c2", "type": "bool"},
                            ],
                        },
                        {"name": "b2", "type": "string"},
                    ],
                },
            ],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def only_unindexed_event():
    return EVENT(
        {
            "inputs": [
                {"indexed": False, "name": "a1", "type": "int16"},
                {"indexed": False, "name": "a2", "type": "string"},
                {"indexed": False, "name": "a3", "type": "bool[3]"},
                {"indexed": False, "name": "a4", "type": "bool[]"},
            ],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def mixed_indexed_unindexed_event():
    return EVENT(
        {
            "inputs": [
                {"indexed": False, "name": "a1", "type": "int16"},
                {"indexed": False, "name": "a2", "type": "string"},
                {"indexed": False, "name": "a3", "type": "bool[3]"},
                {"indexed": False, "name": "a4", "type": "bool[]"},
                {"indexed": True, "name": "b1", "type": "bool"},
                {"indexed": True, "name": "b2", "type": "bool"},
                {"indexed": True, "name": "b3", "type": "bytes"},
            ],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def too_much_indexed_event():
    return EVENT(
        {
            "inputs": [
                {"indexed": True, "name": "a1", "type": "bool"},
                {"indexed": True, "name": "a2", "type": "bool"},
                {"indexed": True, "name": "a3", "type": "bool"},
                {"indexed": True, "name": "a4", "type": "bool"},
            ],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def too_much_indexed_anon_event():
    return EVENT(
        {
            "inputs": [
                {"indexed": True, "name": "a1", "type": "bool"},
                {"indexed": True, "name": "a2", "type": "bool"},
                {"indexed": True, "name": "a3", "type": "bool"},
                {"indexed": True, "name": "a4", "type": "bool"},
                {"indexed": True, "name": "a5", "type": "bool"},
            ],
            "name": "E4",
            "type": "event",
        }
    )


@pytest.fixture()
def multi_inputs_event():
    return EVENT(
        {
            "inputs": [
                {"name": "from", "indexed": True, "type": "address"},
                {"name": "value", "indexed": False, "type": "uint256"},
                {"name": "to", "indexed": True, "type": "address"},
                {"name": "value2", "indexed": False, "type": "uint64"},
            ],
            "name": "MyEvent",
            "type": "event",
        }
    )


@pytest.fixture()
def foo_enc():
    return bytes.fromhex(
        "20".rjust(64, "0") + "3".rjust(64, "0") + "666f6f".ljust(64, "0")
    )


@pytest.fixture()
def true_enc():
    return b"\x01".rjust(32, b"\x00")


# ***********************************************************


def test_event_basic_decode(simple_event_no_hash, foo_enc, true_enc):
    e = Event(simple_event_no_hash)

    assert (
        e.signature.hex()
        == "47b78f0ec63d97830ace2babb45e6271b15a678528e901a9651e45b65105e6c2"
    )

    assert e.decode(foo_enc, [e.signature, true_enc]).to_dict() == {
        "a1": 1,
        "a2": "foo",
    }

    with pytest.raises(ValueError, match=r"First topic.+ signature"):
        e.decode(foo_enc, [b"\x00", true_enc])

    with pytest.raises(ValueError, match=r"Invalid topics count"):
        e.decode(foo_enc, [e.signature])
    with pytest.raises(ValueError, match=r"Invalid topics count"):
        e.decode(foo_enc, [e.signature, true_enc, true_enc])

    assert e.decode(foo_enc, [e.signature, None]).to_dict() == {
        "a1": None,
        "a2": "foo",
    }
    with pytest.raises(ValueError, match=r"Invalid topics count"):
        e.decode(foo_enc, [e.signature, true_enc, true_enc])

    assert e.decode(foo_enc, None).to_dict() == {"a1": None, "a2": "foo"}


def test_event_basic_encode(simple_event_no_hash, true_enc):
    e = Event(simple_event_no_hash)

    assert e.encode({"a1": None}) == [e.signature, None]
    assert e.encode({"a1": 1}) == [e.signature, true_enc]

    with pytest.raises(ValueError, match=r".+ expected 1, got 2"):
        e.encode({"a1": 1, "x": 3})

    with pytest.raises(ValueError, match=r"Missing key.+"):
        e.encode({"a2": 1})

    with pytest.raises(TypeError):
        e.encode(1)  # type: ignore[arg-type]


def test_too_much_indexed(too_much_indexed_event, too_much_indexed_anon_event):
    with pytest.raises(ValueError, match="Too much indexed parameters!"):
        Event(too_much_indexed_event)

    with pytest.raises(ValueError, match="Too much indexed parameters!"):
        Event(too_much_indexed_anon_event)


def test_event_anonymous(anonymous_event_no_hash, foo_enc, true_enc):
    e = Event(anonymous_event_no_hash)
    decoded = e.decode(
        foo_enc,
        [true_enc],
    )
    assert decoded.to_dict() == {"a1": 1, "a2": "foo"}
    assert decoded.a1 == 1
    assert decoded.a2 == "foo"
    with pytest.raises(AttributeError):
        decoded.non_existent

    assert e.decode(foo_enc, [None]).to_dict() == {
        "a1": None,
        "a2": "foo",
    }
    with pytest.raises(ValueError, match=r"Invalid topics count"):
        e.decode(foo_enc, [e.signature, None])

    assert e.decode(foo_enc, None).to_dict() == {"a1": None, "a2": "foo"}

    assert e.encode({"a1": 1}) == [true_enc]
    assert e.encode([1]) == [true_enc]


def test_event_hashed(simple_event_hash):
    e = Event(simple_event_hash)
    hashed = cry.keccak256([b"hello"])[0]

    assert e.encode({"a1": "hello"}) == [e.signature, hashed]

    assert e.decode(b"\x00", [e.signature, hashed]).to_dict() == {"a1": hashed}


def test_simple_int_event(simple_event_int, true_enc):
    e = Event(simple_event_int)
    assert (
        e.signature.hex()
        == "e96585649d926cc4f5031a6113d7494d766198c0ac68b04eb93207460f9d7fd2"
    )

    assert e.encode({"a1": 1}) == [
        e.signature,
        true_enc,
    ]

    assert e.decode(
        bytes.fromhex("00"),
        [e.signature, true_enc],
    ).to_dict() == {"a1": 1}


def test_event_tuple_abiv2(tuple_event, true_enc):
    e = Event(tuple_event)

    expected = [
        e.signature,
        cry.keccak256(
            [
                b"bar1".ljust(32, b"\x00")
                + b"bar2".ljust(32, b"\x00")
                + b"\x08".rjust(32, b"\x00")
            ]
        )[0],
        cry.keccak256([b"baz"])[0],
    ]
    given = e.encode([("bar1", "bar2", 8), b"baz"])
    assert [(d.hex() if d is not None else None) for d in given] == [
        d.hex() for d in expected
    ]

    assert e.decode(true_enc, expected).to_dict() == {
        "a1": expected[1],
        "a2": expected[2],
        "a3": True,
    }


def test_event_tuple_dynarr_abiv2(tuple_dynamic_array_event, true_enc):
    e = Event(tuple_dynamic_array_event)
    expected = [
        e.signature,
        cry.keccak256(
            [
                b"bar1".ljust(32, b"\x00")
                + b"bar2".ljust(32, b"\x00")
                + b"\x08".rjust(32, b"\x00"),
                b"bar3".ljust(32, b"\x00")
                + b"bar4".ljust(32, b"\x00")
                + b"\x07".rjust(32, b"\x00"),
                b"bar5".ljust(32, b"\x00")
                + b"bar6".ljust(32, b"\x00")
                + b"\x06".rjust(32, b"\x00"),
            ]
        )[0],
        cry.keccak256([b"baz"])[0],
    ]
    given = e.encode(
        [
            (
                ("bar1", "bar2", 8),
                ("bar3", "bar4", 7),
                ("bar5", "bar6", 6),
            ),
            "baz",
        ]
    )

    assert [(d.hex() if d is not None else None) for d in given] == [
        d.hex() for d in expected
    ]

    assert e.decode(true_enc, expected).to_dict() == {
        "a1": expected[1],
        "a2": expected[2],
        "a3": True,
    }


def test_event_tuple_fixarr_abiv2(tuple_fixed_array_event):
    e = Event(tuple_fixed_array_event)
    expected = [
        e.signature,
        cry.keccak256(
            [
                b"bar1".ljust(32, b"\x00")
                + b"bar2".ljust(32, b"\x00")
                + b"\x08".rjust(32, b"\x00"),
                b"bar3".ljust(32, b"\x00")
                + b"bar4".ljust(32, b"\x00")
                + b"\x07".rjust(32, b"\x00"),
                b"bar5".ljust(32, b"\x00")
                + b"bar6".ljust(32, b"\x00")
                + b"\x06".rjust(32, b"\x00"),
            ]
        )[0],
        cry.keccak256([b"baz"])[0],
    ]
    given = e.encode(
        [
            (
                ("bar1", "bar2", 8),
                ("bar3", "bar4", 7),
                ("bar5", "bar6", 6),
            ),
            "baz",
        ]
    )
    assert [(d.hex() if d is not None else None) for d in given] == [
        d.hex() for d in expected
    ]

    assert e.decode(b"\x00" * 32, expected).to_dict() == {
        "a1": expected[1],
        "a2": expected[2],
        "a3": False,
    }


def test_event_fixarr_abiv2(fixed_array_event):
    e = Event(fixed_array_event)
    expected = [
        e.signature,
        cry.keccak256(
            [
                b"\x07".rjust(32, b"\x00")
                + b"\x08".rjust(32, b"\x00")
                + b"\x09".rjust(32, b"\x00")
            ]
        )[0],
    ]
    given = e.encode([[7, 8, 9]])
    assert [(d.hex() if d is not None else None) for d in given] == [
        d.hex() for d in expected
    ]

    assert e.decode(b"\x00", expected).to_dict() == {"a1": expected[1]}


def test_event_dynarr_abiv2(dynamic_array_event):
    e = Event(dynamic_array_event)
    expected = [
        e.signature,
        cry.keccak256(
            [
                b"\x07".rjust(32, b"\x00")
                + b"\x08".rjust(32, b"\x00")
                + b"\x09".rjust(32, b"\x00")
            ]
        )[0],
    ]
    given = e.encode([[7, 8, 9]])
    assert [(d.hex() if d is not None else None) for d in given] == [
        d.hex() for d in expected
    ]

    assert e.decode(b"\x00", expected).to_dict() == {
        "a1": expected[1],
    }


def test_decode_only_unindexed(only_unindexed_event):
    e = Event(only_unindexed_event)

    expected_data = {
        "a1": 7,
        "a2": "foo",
        "a3": (True, True, False),
        "a4": (False, True),
    }
    encoded = (
        # a1
        b"\x07".rjust(32, b"\x00")
        # * a2
        + b"\xc0".rjust(32, b"\x00")
        # a3
        + b"\x01".rjust(32, b"\x00") * 2
        + b"\x00".rjust(32, b"\x00")
        # * a4
        + b"\x01\x00".rjust(32, b"\x00")
        # len(a2)
        + b"\x03".rjust(32, b"\x00")
        # a2
        + b"foo".ljust(32, b"\x00")
        # len(a4)
        + b"\x02".rjust(32, b"\x00")
        # a4
        + b"\x00".rjust(32, b"\x00")
        + b"\x01".rjust(32, b"\x00")
    )

    # Don't trust myself
    assert (
        Coder.encode_list(
            ["int", "string", "bool[3]", "bool[]"], list(expected_data.values())
        ).hex()
        == encoded.hex()
    )

    assert e.decode(encoded, [e.signature]).to_dict() == expected_data


def test_decode_mixed(mixed_indexed_unindexed_event):
    e = Event(mixed_indexed_unindexed_event)

    coded_str = cry.keccak256([b"bazz"])[0]
    indexed_enc = [b"\x01".rjust(32, b"\x00")] * 2 + [coded_str]

    expected_data = {
        # Unindexed
        "a1": 7,
        "a2": "foo",
        "a3": (True, True, False),
        "a4": (False, True),
        # Indexed, but not hashed
        "b1": True,
        "b2": True,
        # Indexed, hashed
        "b3": coded_str,
    }

    encoded = (
        # a1
        b"\x07".rjust(32, b"\x00")
        # *a2
        + b"\xc0".rjust(32, b"\x00")
        # a3
        + b"\x01".rjust(32, b"\x00") * 2
        + b"\x00".rjust(32, b"\x00")
        # *a4
        + b"\x01\x00".rjust(32, b"\x00")
        # len(a2)
        + b"\x03".rjust(32, b"\x00")
        # a2
        + b"foo".ljust(32, b"\x00")
        # len(a4)
        + b"\x02".rjust(32, b"\x00")
        # a4
        + b"\x00".rjust(32, b"\x00")
        + b"\x01".rjust(32, b"\x00")
    )

    assert (
        Coder.encode_list(
            ["int", "string", "bool[3]", "bool[]"], list(expected_data.values())[:4]
        ).hex()
        == encoded.hex()
    )

    assert e.decode(encoded, [e.signature, *indexed_enc]).to_dict() == expected_data


def test_decode_struct_unindexed(unindexed_struct_event):
    e = Event(unindexed_struct_event)

    expected_data = {"a1": {"b1": True, "b2": "bar"}}

    encoded = (
        b""
        + b"\x20".rjust(32, b"\x00")  # Start of meaningful part
        + b"\x01".rjust(32, b"\x00")
        + b"\x40".rjust(32, b"\x00")
        + b"\x03".rjust(32, b"\x00")
        + b"bar".ljust(32, b"\x00")
    )
    assert (
        Coder.encode_single("(bool,string)", list(expected_data["a1"].values())).hex()
        == encoded.hex()
    )

    assert e.decode(encoded, [e.signature]).to_dict() == expected_data


def test_decode_struct_fixarray_unindexed(unindexed_struct_fixed_array_event):
    e = Event(unindexed_struct_fixed_array_event)

    expected_data = {
        "a1": [
            {"b1": True, "b2": "bar1"},
            {"b1": False, "b2": "bar2"},
            {"b1": True, "b2": "bar3"},
        ]
    }

    encoded = (
        b""
        # headers
        + b"\x20".rjust(32, b"\x00")
        + b"\x60".rjust(32, b"\x00")
        + b"\xe0".rjust(32, b"\x00")
        + b"\x01\x60".rjust(32, b"\x00")
        # 1st
        + b"\x01".rjust(32, b"\x00")
        + b"\x40".rjust(32, b"\x00")
        + b"\x04".rjust(32, b"\x00")
        + b"bar1".ljust(32, b"\x00")
        # 2nd
        + b"\x00".rjust(32, b"\x00")
        + b"\x40".rjust(32, b"\x00")
        + b"\x04".rjust(32, b"\x00")
        + b"bar2".ljust(32, b"\x00")
        # 3rd
        + b"\x01".rjust(32, b"\x00")
        + b"\x40".rjust(32, b"\x00")
        + b"\x04".rjust(32, b"\x00")
        + b"bar3".ljust(32, b"\x00")
    )
    assert (
        Coder.encode_single(
            "(bool,string)[3]", [list(d.values()) for d in expected_data["a1"]]
        ).hex()
        == encoded.hex()
    )

    assert e.decode(encoded, [e.signature]).to_dict() == expected_data


def test_decode_struct_dynarray_unindexed(unindexed_struct_dynamic_array_event):
    e = Event(unindexed_struct_dynamic_array_event)

    expected_data = {
        "a1": [
            {"b1": True, "b2": "bar1"},
            {"b1": False, "b2": "bar2"},
            {"b1": True, "b2": "bar3"},
        ]
    }

    encoded = (
        b""
        # headers
        + b"\x20".rjust(32, b"\x00")
        + b"\x03".rjust(32, b"\x00")  # length
        + b"\x60".rjust(32, b"\x00")
        + b"\xe0".rjust(32, b"\x00")
        + b"\x01\x60".rjust(32, b"\x00")
        # 1st
        + b"\x01".rjust(32, b"\x00")
        + b"\x40".rjust(32, b"\x00")
        + b"\x04".rjust(32, b"\x00")
        + b"bar1".ljust(32, b"\x00")
        # 2nd
        + b"\x00".rjust(32, b"\x00")
        + b"\x40".rjust(32, b"\x00")
        + b"\x04".rjust(32, b"\x00")
        + b"bar2".ljust(32, b"\x00")
        # 3rd
        + b"\x01".rjust(32, b"\x00")
        + b"\x40".rjust(32, b"\x00")
        + b"\x04".rjust(32, b"\x00")
        + b"bar3".ljust(32, b"\x00")
    )
    assert (
        Coder.encode_single(
            "(bool,string)[]", [list(d.values()) for d in expected_data["a1"]]
        ).hex()
        == encoded.hex()
    )

    assert e.decode(encoded, [e.signature]).to_dict() == expected_data


def test_decode_struct_nested_unindexed(unindexed_struct_nested_event):
    e = Event(unindexed_struct_nested_event)

    expected_data = {
        "a1": [
            {"b1": {"c1": True, "c2": False}, "b2": "bar1"},
            {"b1": {"c1": False, "c2": True}, "b2": "bar2"},
        ]
    }

    encoded = (
        b""
        # headers
        + b"\x20".rjust(32, b"\x00")
        + b"\x02".rjust(32, b"\x00")  # length
        + b"\x40".rjust(32, b"\x00")
        + b"\xe0".rjust(32, b"\x00")
        # 1st
        + b"\x01".rjust(32, b"\x00")
        + b"\x00".rjust(32, b"\x00")
        + b"\x60".rjust(32, b"\x00")
        + b"\x04".rjust(32, b"\x00")
        + b"bar1".ljust(32, b"\x00")
        # 2nd
        + b"\x00".rjust(32, b"\x00")
        + b"\x01".rjust(32, b"\x00")
        + b"\x60".rjust(32, b"\x00")
        + b"\x04".rjust(32, b"\x00")
        + b"bar2".ljust(32, b"\x00")
    )
    assert (
        Coder.encode_single(
            "((bool,bool),string)[]", [((True, False), "bar1"), ((False, True), "bar2")]
        ).hex()
        == encoded.hex()
    )

    assert e.decode(encoded, [e.signature]).to_dict() == expected_data


def test_encode_full(multi_inputs_event):
    event = Event(multi_inputs_event)
    address_from = "0x" + "f" * 40
    address_to = "0x" + "9" * 40

    topics_enc = event.encode([address_from, address_to])
    data_enc = event.encode_data([256, 127])

    topics, data = event.encode_full([address_from, 256, address_to, 127])
    assert topics == topics_enc
    assert data == data_enc

    topics, data = event.encode_full(
        {
            "to": address_to,
            "value": 256,
            "value2": 127,
            "from": address_from,
        }
    )
    assert topics == topics_enc
    assert data == data_enc

    with pytest.raises(ValueError, match=".+ shorter .+"):
        event.encode_full([address_from, 256, address_to, 127, 0])
    with pytest.raises(ValueError, match=".+ shorter .+"):
        event.encode_full([1, address_from, 256, address_to, 127])

    with pytest.raises(ValueError, match="Invalid keys count"):
        event.encode_full(
            {
                "to": address_to,
                "value": 256,
                "value2": 127,
                "from": address_from,
                "x": 1,
            }
        )

    with pytest.raises(ValueError, match="Key 'from' is missing"):
        event.encode_full(
            {
                "to": address_to,
                "value": 256,
                "value2": 127,
            }
        )

    with pytest.raises(ValueError, match="Key 'from' is missing"):
        event.encode_full(
            {
                "to": address_to,
                "value": 256,
                "value2": 127,
                "not_address_from": address_from,
            }
        )

    with pytest.raises(TypeError):
        event.encode_full(1)  # type: ignore[arg-type]


def test_encode_data(multi_inputs_event):
    event = Event(multi_inputs_event)

    enc = event.encode_data([256, 129])  # 256 == 0x100, 129 == 0x81
    assert enc.hex() == "100".rjust(64, "0") + "81".rjust(64, "0")

    enc = event.encode_data({"value": 256, "value2": 129})
    assert enc.hex() == "100".rjust(64, "0") + "81".rjust(64, "0")


def test_from_text_ok(anonymous_event_no_hash):
    code = R"""
    contract A {
        event E2(uint indexed a1, string a2) anonymous;
    }
    """
    e = Event.from_solidity(text=code)
    assert e._definition == anonymous_event_no_hash


def test_from_file_ok(anonymous_event_no_hash):
    code = R"""
    contract A {
        event E2(uint indexed a1, string a2) anonymous;
    }
    """
    fd, fpath = mkstemp(text=True)
    with os.fdopen(fd, "w") as f:
        f.write(code)

    e = Event.from_solidity(file=fpath)
    assert e._definition == anonymous_event_no_hash


def test_missing_kind(anonymous_event_no_hash):
    code = R"""
    contract A {
        function f() public pure returns (int) {}
    }
    """
    with pytest.raises(ValueError, match="Missing value"):
        Event.from_solidity(text=code)


def test_mulitple_kind(anonymous_event_no_hash):
    code = R"""
    contract A {
        event E1(uint indexed a1, string a2) anonymous;
        event E2(uint indexed a1, string a2) anonymous;
    }
    """
    with pytest.raises(ValueError, match="Ambiguous input"):
        Event.from_solidity(text=code)


def test_invalid_code(anonymous_event_no_hash):
    code = R"""
    contract A {
        event E1(uint indexed a1, string a2) anonymous ?;
    }
    """
    with pytest.raises(SolcError):
        Event.from_solidity(text=code)
