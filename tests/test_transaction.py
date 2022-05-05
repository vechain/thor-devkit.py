import pytest
from voluptuous.error import Invalid

import thor_devkit.transaction  # noqa: F401  # Used for mocking
from thor_devkit import cry
from thor_devkit.exceptions import (
    BadTransaction,
    DeserializationError,
    SerializationError,
)
from thor_devkit.transaction import Transaction, TransactionBodyT


@pytest.fixture()
def non_delegated_body() -> TransactionBodyT:
    return {
        "chainTag": 1,
        "blockRef": "0x00000000aabbccdd",
        "expiration": 32,
        "clauses": [
            {
                "to": "0x7567d83b7b8d80addcb281a71d54fc7b3364ffed",
                "value": 10000,
                "data": "0x000000606060",
            },
            {
                "to": "0x7567d83b7b8d80addcb281a71d54fc7b3364ffed",
                "value": 20000,
                "data": "0x000000606060",
            },
        ],
        "gasPriceCoef": 128,
        "gas": 21000,
        "dependsOn": None,
        "nonce": 12345678,
    }


@pytest.fixture()
def unsigned_non_delegated_tx(non_delegated_body):
    return Transaction(non_delegated_body)


@pytest.fixture()
def unsigned_non_delegated_encoded(non_delegated_body):
    return bytes.fromhex(
        "f8540184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ff"
        "ed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ff"
        "ed824e208600000060606081808252088083bc614ec0"
    )


@pytest.fixture()
def signed_non_delegated_encoded(non_delegated_body):
    return bytes.fromhex(
        "f8970184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ff"
        "ed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ff"
        "ed824e208600000060606081808252088083bc614ec0b841f76f3c91a8341658"
        "72aa9464fc55b03a13f46ea8d3b858e528fcceaf371ad6884193c3f313ff8eff"
        "bb57fe4d1adc13dceb933bedbf9dbb528d2936203d5511df00"
    )


@pytest.fixture()
def private_key():
    return bytes.fromhex(
        "7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a"
    )


@pytest.fixture()
def signed_non_delegated_tx(non_delegated_body, private_key):
    signed = Transaction(non_delegated_body)
    _a, _ = cry.blake2b256([signed.encode()])
    _b = cry.secp256k1.sign(_a, private_key)
    signed.signature = _b
    return signed


@pytest.fixture()
def signer(private_key):
    return cry.public_key_to_address(cry.secp256k1.derive_public_key(private_key))


@pytest.fixture()
def delegated_body() -> TransactionBodyT:
    return {
        "chainTag": 1,
        "blockRef": "0x00000000aabbccdd",
        "expiration": 32,
        "clauses": [
            {
                "to": "0x7567d83b7b8d80addcb281a71d54fc7b3364ffed",
                "value": 10000,
                "data": "0x000000606060",
            },
            {
                "to": "0x7567d83b7b8d80addcb281a71d54fc7b3364ffed",
                "value": 20000,
                "data": "0x000000606060",
            },
        ],
        "gasPriceCoef": 128,
        "gas": 21000,
        "dependsOn": None,
        "nonce": 12345678,
        "reserved": {"features": 1, "unused": [b"1234"]},
    }


@pytest.fixture()
def unsigned_delegated_tx(delegated_body):
    return Transaction(delegated_body)


def test_unsigned(unsigned_non_delegated_tx, unsigned_non_delegated_encoded):
    unsigned = unsigned_non_delegated_tx

    x = unsigned.encode()
    signing_hash, _ = cry.blake2b256([x])
    assert (
        signing_hash.hex()
        == "2a1c25ce0d66f45276a5f308b99bf410e2fc7d5b6ea37a49f2ab9f1da9446478"
    )

    assert (
        unsigned.get_signing_hash().hex()
        == "2a1c25ce0d66f45276a5f308b99bf410e2fc7d5b6ea37a49f2ab9f1da9446478"
    )

    assert not unsigned.is_delegated

    assert unsigned.intrinsic_gas == 37432

    assert unsigned.id is None
    assert unsigned.signature is None
    assert unsigned.origin is None

    assert unsigned.encode().hex() == unsigned_non_delegated_encoded.hex()

    assert Transaction.decode(unsigned_non_delegated_encoded, True) == unsigned


def test_unsigned_gas_1(non_delegated_body):
    non_delegated_body["clauses"] = []

    assert Transaction(non_delegated_body).intrinsic_gas == 21000


def test_unsigned_gas_2(non_delegated_body):
    non_delegated_body["clauses"] = [{"to": None, "value": 0, "data": "0x"}]

    assert Transaction(non_delegated_body).intrinsic_gas == 53000


def test_empty_data(non_delegated_body):
    non_delegated_body["clauses"][0]["data"] = "0x"
    Transaction(non_delegated_body).encode()


def test_invalid_body_1(non_delegated_body: TransactionBodyT):
    non_delegated_body["chainTag"] = 256
    with pytest.raises(SerializationError, match=r".+too large.+"):
        Transaction(non_delegated_body).encode()


def test_invalid_body_2(non_delegated_body: TransactionBodyT):
    non_delegated_body["chainTag"] = -1
    with pytest.raises(SerializationError, match=r".+negative.+"):
        Transaction(non_delegated_body).encode()


def test_invalid_body_3(non_delegated_body: TransactionBodyT):
    non_delegated_body["chainTag"] = 1.1  # type: ignore
    with pytest.raises(Invalid):
        Transaction(non_delegated_body).encode()


def test_invalid_body_4(non_delegated_body: TransactionBodyT):
    non_delegated_body["blockRef"] = "0x"
    with pytest.raises(SerializationError, match=r"Expected string of length 18"):
        Transaction(non_delegated_body).encode()


def test_invalid_body_5(non_delegated_body: TransactionBodyT):
    non_delegated_body["blockRef"] = "0x" + "0" * 18
    with pytest.raises(SerializationError, match=r"Expected string of length 18"):
        Transaction(non_delegated_body).encode()


def test_invalid_body_6(non_delegated_body: TransactionBodyT):
    non_delegated_body["expiration"] = 2**32
    with pytest.raises(SerializationError, match=r".+too large.+"):
        Transaction(non_delegated_body).encode()


def test_invalid_body_7(non_delegated_body: TransactionBodyT):
    non_delegated_body["expiration"] = -1
    with pytest.raises(SerializationError, match=r".+negative.+"):
        Transaction(non_delegated_body).encode()


def test_invalid_body_8(non_delegated_body: TransactionBodyT):
    non_delegated_body["expiration"] = 1.1  # type: ignore
    with pytest.raises(Invalid):
        Transaction(non_delegated_body).encode()


def test_invalid_body_9(non_delegated_body: TransactionBodyT):
    non_delegated_body["gasPriceCoef"] = 256
    with pytest.raises(SerializationError, match=r".+too large.+"):
        Transaction(non_delegated_body).encode()


def test_invalid_body_10(non_delegated_body: TransactionBodyT):
    non_delegated_body["gasPriceCoef"] = -1
    with pytest.raises(SerializationError, match=r".+negative.+"):
        Transaction(non_delegated_body).encode()


def test_invalid_body_11(non_delegated_body: TransactionBodyT):
    non_delegated_body["gasPriceCoef"] = 1.1  # type: ignore
    with pytest.raises(Invalid):
        Transaction(non_delegated_body).encode()


def test_invalid_body_12(non_delegated_body: TransactionBodyT):
    non_delegated_body["gas"] = "0x10000000000000000"
    with pytest.raises(SerializationError, match=r".+too large.+"):
        Transaction(non_delegated_body).encode()


def test_invalid_body_13(non_delegated_body: TransactionBodyT):
    non_delegated_body["nonce"] = "0x10000000000000000"
    with pytest.raises(SerializationError, match=r".+too large.+"):
        Transaction(non_delegated_body).encode()


def test_reserved_with_untrimmed_bytes(non_delegated_body):
    non_delegated_body["reserved"] = {"features": 0, "unused": [b""]}
    untrimmed_enc = bytes.fromhex(
        "f8560184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed"
        "82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed82"
        "4e208600000060606081808252088083bc614ec28080"
    )
    trimmed_enc = bytes.fromhex(
        "f8540184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed"
        "82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed82"
        "4e208600000060606081808252088083bc614ec0"
    )
    assert Transaction(non_delegated_body).encode().hex() == trimmed_enc.hex()
    with pytest.raises(BadTransaction):
        Transaction.decode(untrimmed_enc, unsigned=True)


def test_signed(signed_non_delegated_tx, signer):
    signed = signed_non_delegated_tx

    assert signed.signature
    assert signed.signature.hex() == (
        "f76f3c91a834165872aa9464fc55b03a13f46ea8d3b858e528fcceaf371ad6884"
        "193c3f313ff8effbb57fe4d1adc13dceb933bedbf9dbb528d2936203d5511df00"
    )
    assert signed.origin == "0x" + signer.hex()
    assert (
        signed.id
        == "0xda90eaea52980bc4bb8d40cb2ff84d78433b3b4a6e7d50b75736c5e3e77b71ec"
    )
    assert (
        signed.get_signing_hash("0x" + signer.hex()).hex()
        == "da90eaea52980bc4bb8d40cb2ff84d78433b3b4a6e7d50b75736c5e3e77b71ec"
    )


def test_encode_decode(
    signed_non_delegated_tx,
    signed_non_delegated_encoded,
    unsigned_non_delegated_encoded,
):
    assert signed_non_delegated_tx.encode().hex() == signed_non_delegated_encoded.hex()
    assert (
        Transaction.decode(signed_non_delegated_encoded, False)
        == signed_non_delegated_tx
    )

    with pytest.raises(DeserializationError):
        Transaction.decode(unsigned_non_delegated_encoded, False)

    with pytest.raises(DeserializationError):
        Transaction.decode(signed_non_delegated_encoded, True)


def test_incorrectly_signed_non_delegated(non_delegated_body):
    tx = Transaction(non_delegated_body)
    tx.signature = bytes([1, 2, 3])
    assert tx.origin is None
    assert tx.id is None

    tx.signature = bytes(range(65))
    assert tx.origin is None
    assert tx.id is None
    assert tx.delegator is None


def test_incorrectly_signed_delegated(delegated_body, mocker):
    tx = Transaction(delegated_body)
    tx.signature = bytes([1, 2, 3])
    assert tx.origin is None
    assert tx.id is None
    assert tx.delegator is None

    mocker.patch(
        "thor_devkit.transaction.Transaction.origin",
        new_callable=mocker.PropertyMock,
        return_value="0x" + bytes(range(64)).hex(),
    )
    tx = Transaction(delegated_body)
    tx.signature = bytes(range(65 * 2))
    assert tx.origin is not None
    assert tx.delegator is None

    mocker.patch(
        "thor_devkit.transaction.Transaction.origin",
        new_callable=mocker.PropertyMock,
        return_value=None,
    )
    tx = Transaction(delegated_body)
    tx.signature = bytes(range(65 * 2))
    assert tx.is_delegated
    assert tx._signature_is_valid()
    assert tx.origin is None
    assert tx.delegator is None


def test_features(unsigned_delegated_tx):
    assert unsigned_delegated_tx.is_delegated
    assert unsigned_delegated_tx != {}

    # Sender
    # priv_1 = cry.secp256k1.generate_privateKey()
    priv_1 = bytes.fromhex(
        "58e444d4fe08b0f4d9d86ec42f26cf15072af3ddc29a78e33b0ceaaa292bcf6b"
    )
    addr_1 = cry.public_key_to_address(cry.secp256k1.derive_public_key(priv_1))

    # Gas payer
    # priv_2 = cry.secp256k1.generate_privateKey()
    priv_2 = bytes.fromhex(
        "0bfd6a863f347f4ef2cf2d09c3db7b343d84bb3e6fc8c201afee62de6381dc65"
    )
    addr_2 = cry.public_key_to_address(cry.secp256k1.derive_public_key(priv_2))

    h = unsigned_delegated_tx.get_signing_hash()
    dh = unsigned_delegated_tx.get_signing_hash("0x" + addr_1.hex())

    # Concat two parts to forge a signature.
    sig = cry.secp256k1.sign(h, priv_1) + cry.secp256k1.sign(dh, priv_2)

    unsigned_delegated_tx.signature = sig

    assert unsigned_delegated_tx.origin == "0x" + addr_1.hex()
    assert unsigned_delegated_tx.delegator == "0x" + addr_2.hex()


# Well this is a dangerous part, we tests the "private" function.
# Shouldn't recommend you to do the same, but I need to test it.
def test_unused_1(delegated_body):
    delegated_body["reserved"]["unused"] = [
        bytes.fromhex("0F0F"),
        bytes.fromhex("0101"),
    ]
    delegated_tx = Transaction(delegated_body)
    assert delegated_tx.is_delegated
    assert Transaction.decode(delegated_tx.encode(), True) == delegated_tx

    reserved_list = delegated_tx._encode_reserved()
    assert reserved_list == [
        bytes.fromhex("01"),
        bytes.fromhex("0F0F"),
        bytes.fromhex("0101"),
    ]


def test_unused_2(delegated_body):
    delegated_body["reserved"]["unused"] = [bytes.fromhex("0F0F"), bytes(0)]
    delegated_tx = Transaction(delegated_body)
    assert delegated_tx.is_delegated

    reserved_list = delegated_tx._encode_reserved()
    assert reserved_list == [bytes.fromhex("01"), bytes.fromhex("0F0F")]
    assert Transaction.decode(delegated_tx.encode(), True) == delegated_tx


def test_body_copy(non_delegated_body):
    tx = Transaction(non_delegated_body)
    b1 = tx.get_body(False)
    b2 = tx.get_body(True)

    assert b1 is not b2  # id should be different
    assert b1 == b2  # content should be the same
