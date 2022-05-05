import re

import pytest

from thor_devkit import cry
from thor_devkit.cry import keystore, mnemonic, secp256k1, utils


@pytest.fixture(
    params=[
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0XD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ]
)
def address(request):
    return request.param


@pytest.fixture()
def public_key():
    return bytes.fromhex(
        "04b90e9bb2617387eba4502c730de65a33878ef384a46f1096d86f2da19043304"
        "afa67d0ad09cf2bea0c6f2d1767a9e62a7a7ecc41facf18f2fa505d92243a658f"
    )


@pytest.fixture()
def private_key():
    return bytes.fromhex(
        "7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a"
    )


@pytest.fixture()
def seed_phrase():
    return (
        "ignore empty bird silly journey junior ripple have guard waste between tenant"
    )


def test_remove_0x_1(address: str):
    assert utils.remove_0x(address)[:2] not in {"0x", "0X"}


def test_remove_0x_2():
    # no 0x at all, same length
    p = "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
    assert utils.remove_0x(p) == p

    # 0x in the middle, other length
    p = "12A10x12"
    assert utils.remove_0x(p) == p


def test_blake2b():
    expected = "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610"

    h, _ = cry.blake2b256([b"hello world"])
    assert h.hex() == expected

    h, _ = cry.blake2b256([b"hello", b" world"])
    assert h.hex() == expected


def test_keccak256():
    expected = "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"

    h, _ = cry.keccak256([b"hello world"])
    assert h.hex() == expected

    h, _ = cry.keccak256([b"hello", b" world"])
    assert h.hex() == expected


def test_address(address: str):
    assert cry.is_address(address)
    assert cry.to_checksum_address(address) == re.sub(r"^(0X)", r"0x", address)


def test_private_key_length(private_key: bytes):
    private_key = secp256k1.generate_private_key()
    assert len(private_key) == 32


def test_derive_public_key(public_key: bytes, private_key: bytes):
    _pub = secp256k1.derive_public_key(private_key)
    assert public_key.hex() == _pub.hex()


def test_public_key_to_address(public_key: bytes):
    address = cry.public_key_to_address(public_key)
    assert "0x" + address.hex() == "0xd989829d88b0ed1b06edf5c50174ecfa64f14a64"


def test_sign_hash(public_key: bytes, private_key: bytes):
    msg_hash, _ = cry.keccak256([b"hello world"])

    sig = cry.secp256k1.sign(msg_hash, private_key)
    assert sig.hex() == (
        "f8fe82c74f9e1f5bf443f8a7f8eb968140f554968fdcab0a6ffe904e451c8b924"
        "4be44bccb1feb34dd20d9d8943f8c131227e55861736907b02d32c06b934d7200"
    )

    _pub = cry.secp256k1.recover(msg_hash, sig)
    assert _pub.hex() == public_key.hex()


def test_mnemonic(seed_phrase):
    SEED = (
        "28bc19620b4fbb1f8892b9607f6e406fcd8226a0d6dc167ff677d122a1a64ef9"
        "36101a644e6b447fd495677f68215d8522c893100d9010668614a68b3c7bb49f"
    )
    PRIV = "27196338e7d0b5e7bf1be1c0327c53a244a18ef0b102976980e341500f492425"

    # Random Generate.
    _words = mnemonic.generate()
    assert len(_words) == 12

    # Valid: True
    words = seed_phrase.split(" ")
    assert mnemonic.is_valid(words)

    # Valid: True
    assert mnemonic.is_valid(mnemonic.generate())

    # Valid: False
    words2 = "hello word".split(" ")
    assert not mnemonic.is_valid(words2)

    # Valid: False
    words3 = sorted(seed_phrase.split(" "))
    assert not mnemonic.is_valid(words3)

    # Seed generated from words.
    assert mnemonic.derive_seed(words) == bytes.fromhex(SEED)

    # First Private Key generated from words.
    assert mnemonic.derive_private_key(words, 0) == bytes.fromhex(PRIV)


def test_keystore():
    ks: keystore.KeyStoreT = {
        "version": 3,
        "id": "f437ebb1-5b0d-4780-ae9e-8640178ffd77",
        "address": "dc6fa3ec1f3fde763f4d59230ed303f854968d26",
        "crypto": {
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": 32,
                "salt": (
                    "b57682e5468934be81217ad5b14ca74dab2b42c2476864592c9f3b370c09460a"
                ),
                "n": 262144,
                "r": 8,
                "p": 1,
            },
            "cipher": "aes-128-ctr",
            "ciphertext": (
                "88cb876f9c0355a89cad88ee7a17a2179700bc4306eaf78fa67320efbb4c7e31"
            ),
            "cipherparams": {"iv": "de5c0c09c882b3f679876b22b6c5af21"},
            "mac": "8426e8a1e151b28f694849cb31f64cbc9ae3e278d02716cf5b61d7ddd3f6e728",
        },
    }
    password = b"123456"
    private_key_hex = "1599403f7b6c17bb09f16e7f8ebe697af3626db5b41e0f9427a49151c6216920"

    _priv = keystore.decrypt(ks, password)
    assert _priv.hex() == private_key_hex


def test_hdnode(seed_phrase):
    words = seed_phrase.split(" ")

    addresses = [
        "339fb3c438606519e2c75bbf531fb43a0f449a70",
        "5677099d06bc72f9da1113afa5e022feec424c8e",
        "86231b5cdcbfe751b9ddcd4bd981fc0a48afe921",
        "d6f184944335f26ea59dbb603e38e2d434220fcd",
        "2ac1a0aecd5c80fb5524348130ab7cf92670470a",
    ]

    hd_node = cry.HDNode.from_mnemonic(words)

    for idx, address in enumerate(addresses):
        child_node = hd_node.derive(idx)
        assert child_node.address().hex() == address

    priv = hd_node.private_key()
    pub = hd_node.public_key()
    cc = hd_node.chain_code()

    n = cry.HDNode.from_private_key(priv, cc)

    for idx, address in enumerate(addresses):
        child_node = n.derive(idx)
        assert child_node.address().hex() == address

    n2 = cry.HDNode.from_public_key(pub, cc)

    for idx, address in enumerate(addresses):
        child_node = n2.derive(idx)
        assert child_node.address().hex() == address
