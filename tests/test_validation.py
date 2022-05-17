import pytest
from voluptuous.error import Invalid

from thor_devkit.validation import address_type, hex_integer, hex_string


@pytest.fixture(
    params=[
        "0x00",
        "0x01",
        "0x1",
        "0xFFFFFFE",
        "0xFFFffE",
        "0xeeeeee",
        "0x" + "F" * 128,
    ]
)
def integer_prefixed(request):
    return request.param


@pytest.fixture()
def integer_unprefixed(integer_prefixed):
    return integer_prefixed[2:]


def test_hex_integer_no_length_no_prefix(integer_unprefixed):
    assert (
        hex_integer(require_prefix=False)(integer_unprefixed)
        == "0x" + integer_unprefixed.lower()
    )
    assert hex_integer(require_prefix=False, to_int=True)(integer_unprefixed) == int(
        integer_unprefixed, 16
    )


def test_hex_integer_no_length_prefix_allowed(integer_prefixed):
    assert (
        hex_integer(require_prefix=False)(integer_prefixed) == integer_prefixed.lower()
    )
    assert hex_integer(require_prefix=False, to_int=True)(integer_prefixed) == int(
        integer_prefixed, 16
    )

    assert hex_integer()(integer_prefixed) == integer_prefixed.lower()
    assert hex_integer(to_int=True)(integer_prefixed) == int(integer_prefixed, 16)


def test_hex_integer_no_length_prefix_missing(integer_unprefixed):
    with pytest.raises(Invalid, match=r"must start with .0x."):
        hex_integer()(integer_unprefixed)


def test_hex_integer_with_length_prefix_ok(integer_prefixed):
    assert (
        hex_integer(len(integer_prefixed) - 2)(integer_prefixed)
        == integer_prefixed.lower()
    )


def test_hex_integer_with_length_no_prefix_ok(integer_unprefixed):
    assert (
        hex_integer(len(integer_unprefixed), require_prefix=False)(integer_unprefixed)
        == "0x" + integer_unprefixed.lower()
    )


def test_hex_integer_with_length_prefix_longer(integer_prefixed):
    with pytest.raises(Invalid, match=r"Expected.*length"):
        hex_integer(len(integer_prefixed) - 2)(integer_prefixed + "f")


def test_hex_integer_with_length_no_prefix_longer(integer_unprefixed):
    with pytest.raises(Invalid, match=r"Expected.*length"):
        hex_integer(len(integer_unprefixed), require_prefix=False)(
            integer_unprefixed + "f"
        )


def test_hex_integer_with_length_prefix_shorter(integer_prefixed):
    with pytest.raises(Invalid, match=r"Expected.*length"):
        hex_integer(len(integer_prefixed) - 2)(integer_prefixed[:-1])


def test_hex_integer_with_length_no_prefix_shorter(integer_unprefixed):
    with pytest.raises(Invalid, match=r"Expected.*length"):
        hex_integer(len(integer_unprefixed), require_prefix=False)(
            integer_unprefixed[:-1]
        )


def test_hex_integer_empty():
    assert hex_integer(allow_empty=True)("0x") == "0x"
    assert hex_integer(length=0, allow_empty=True)("0x") == "0x"

    assert hex_integer(require_prefix=False, allow_empty=True)("") == "0x"
    assert hex_integer(require_prefix=False, length=0, allow_empty=True)("") == "0x"

    assert hex_integer(require_prefix=False, allow_empty=True)("0x") == "0x"
    assert hex_integer(require_prefix=False, length=0, allow_empty=True)("0x") == "0x"

    with pytest.warns(RuntimeWarning):
        assert hex_integer(length=0)("0x") == "0x"


def test_hex_integer_odd():
    with pytest.raises(Invalid, match="Expected string"):
        hex_integer()(0)  # type: ignore[arg-type]

    with pytest.raises(Invalid, match="Expected string"):
        hex_integer()(object())  # type: ignore[arg-type]

    with pytest.raises(Invalid, match="convertible to number"):
        hex_integer()("0xzz")


# -----------------------------------------------------------------------------


@pytest.fixture(
    params=[
        "0x00",
        "0x01",
        "0xFFFFFF",
        "0xFFFffE",
        "0xeeeeee",
        "0x" + "F" * 128,
    ]
)
def string_prefixed(request):
    return request.param


@pytest.fixture()
def string_unprefixed(string_prefixed):
    return string_prefixed[2:]


def test_hex_string_no_length_no_prefix(string_unprefixed):
    assert hex_string()(string_unprefixed) == string_unprefixed.lower()
    assert hex_string(to_bytes=True)(string_unprefixed) == bytes.fromhex(
        string_unprefixed
    )

    assert hex_string(allow_prefix=True)(string_unprefixed) == string_unprefixed.lower()
    assert hex_string(allow_prefix=True, to_bytes=True)(
        string_unprefixed
    ) == bytes.fromhex(string_unprefixed)


def test_hex_string_no_length_prefix_allowed(string_prefixed):
    assert hex_string(allow_prefix=True)(string_prefixed) == string_prefixed.lower()[2:]
    assert hex_string(allow_prefix=True, to_bytes=True)(
        string_prefixed
    ) == bytes.fromhex(string_prefixed[2:])


def test_hex_string_no_length_prefix_denied(string_prefixed):
    with pytest.raises(Invalid, match=r"without .0x. prefix"):
        hex_string()(string_prefixed)


def test_hex_string_with_length_prefix_ok(string_prefixed):
    assert (
        hex_string(len(string_prefixed) - 2, allow_prefix=True)(string_prefixed)
        == string_prefixed.lower()[2:]
    )


def test_hex_string_with_length_no_prefix_ok(string_unprefixed):
    assert (
        hex_string(len(string_unprefixed))(string_unprefixed)
        == string_unprefixed.lower()
    )


def test_hex_string_with_length_prefix_longer(string_prefixed):
    with pytest.raises(Invalid, match=r"Expected.*length"):
        hex_string(len(string_prefixed) - 2, allow_prefix=True)(string_prefixed + "f")


def test_hex_string_with_length_no_prefix_longer(string_unprefixed):
    with pytest.raises(Invalid, match=r"Expected.*length"):
        hex_string(len(string_unprefixed))(string_unprefixed + "f")


def test_hex_string_with_length_prefix_shorter(string_prefixed):
    with pytest.raises(Invalid, match=r"Expected.*length"):
        hex_string(len(string_prefixed) - 2, allow_prefix=True)(string_prefixed[:-1])


def test_hex_string_with_length_no_prefix_shorter(string_unprefixed):
    with pytest.raises(Invalid, match=r"Expected.*length"):
        hex_string(len(string_unprefixed))(string_unprefixed[:-1])


def test_hex_string_empty():
    assert hex_string(allow_prefix=True, allow_empty=True)("0x") == ""
    assert hex_string(allow_prefix=True, length=0, allow_empty=True)("0x") == ""

    assert hex_string(allow_prefix=True, allow_empty=True)("") == ""
    assert hex_string(allow_prefix=True, length=0, allow_empty=True)("") == ""

    assert hex_string(allow_empty=True)("") == ""
    assert hex_string(length=0, allow_empty=True)("") == ""

    with pytest.warns(RuntimeWarning):
        assert hex_string(length=0)("") == ""


def test_hex_string_odd():
    with pytest.raises(Invalid, match="Expected string"):
        hex_string()(0)  # type: ignore[arg-type]

    with pytest.raises(Invalid, match="Expected string"):
        hex_string()(object())  # type: ignore[arg-type]

    with pytest.raises(Invalid, match="convertible to bytes"):
        hex_string()("zz")


# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "addr",
    [
        "0" * 40,
        "f" * 40,
        "F" * 40,
        "4fa" + "F" * 37,
    ],
)
def test_address_valid(addr):
    assert address_type()(addr) == "0x" + addr.lower()
    assert address_type()("0x" + addr) == "0x" + addr.lower()


def test_address_invalid():
    with pytest.raises(Invalid):
        address_type()(None)  # type: ignore[arg-type]
    with pytest.raises(Invalid):
        address_type()("0x")
    with pytest.raises(Invalid):
        address_type()("")
    with pytest.raises(Invalid):
        address_type()("0x" + "f" * 39)
