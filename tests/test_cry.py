from thor_devkit import cry
from thor_devkit.cry import secp256k1
from thor_devkit.cry import mnemonic
from thor_devkit.cry import keystore


def test_utils():
    address = [
        '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
        '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
        '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
        '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'
    ]

    for addr in address:
        assert cry.utils.remove_0x(addr).startswith('0x') == False

    # no 0x at all
    assert cry.utils.remove_0x(
        'D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb') == 'D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'

    # 0x in the middle
    assert cry.utils.remove_0x(
        'D1220x0A0cf47c7B9Be7A2E6BA89F429762e7b9aDb') == 'D1220x0A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'


def test_blake2b():
    h, _ = cry.blake2b256([b'hello world'])
    assert h.hex() == '256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610'

    h, _ = cry.blake2b256([b'hello', b' world'])
    assert h.hex() == '256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610'


def test_keccak256():
    h, _ = cry.keccak256([b'hello world'])
    assert h.hex() == '47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad'

    h, _ = cry.keccak256([b'hello', b' world'])
    assert h.hex() == '47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad'


def test_address():
    address = [
        '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
        '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
        '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
        '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'
    ]

    for addr in address:
        assert cry.is_address(addr)
        assert cry.to_checksum_address(addr) == addr


def test_private_key():
    private_key = secp256k1.generate_privateKey()
    assert len(private_key) == 32


def test_derive_public_key():
    priv = bytes.fromhex(
        '7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a')
    pub = bytes.fromhex(
        '04b90e9bb2617387eba4502c730de65a33878ef384a46f1096d86f2da19043304afa67d0ad09cf2bea0c6f2d1767a9e62a7a7ecc41facf18f2fa505d92243a658f')
    _pub = secp256k1.derive_publicKey(priv)
    assert pub.hex() == _pub.hex()


def test_public_key_to_address():
    pub = bytes.fromhex(
        '04b90e9bb2617387eba4502c730de65a33878ef384a46f1096d86f2da19043304afa67d0ad09cf2bea0c6f2d1767a9e62a7a7ecc41facf18f2fa505d92243a658f')
    address = cry.public_key_to_address(pub)
    assert '0x' + address.hex() == '0xd989829d88b0ed1b06edf5c50174ecfa64f14a64'


def test_sign_hash():
    pub = bytes.fromhex(
        '04b90e9bb2617387eba4502c730de65a33878ef384a46f1096d86f2da19043304afa67d0ad09cf2bea0c6f2d1767a9e62a7a7ecc41facf18f2fa505d92243a658f')
    priv = bytes.fromhex(
        '7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a')
    msg_hash, _ = cry.keccak256([b'hello world'])

    sig = cry.secp256k1.sign(msg_hash, priv)
    assert sig.hex() == 'f8fe82c74f9e1f5bf443f8a7f8eb968140f554968fdcab0a6ffe904e451c8b9244be44bccb1feb34dd20d9d8943f8c131227e55861736907b02d32c06b934d7200'

    _pub = cry.secp256k1.recover(msg_hash, sig)
    assert _pub.hex() == pub.hex()


def test_mnemonic():
    SENTENCE = 'ignore empty bird silly journey junior ripple have guard waste between tenant'
    SEED = '28bc19620b4fbb1f8892b9607f6e406fcd8226a0d6dc167ff677d122a1a64ef936101a644e6b447fd495677f68215d8522c893100d9010668614a68b3c7bb49f'
    PRIV = '27196338e7d0b5e7bf1be1c0327c53a244a18ef0b102976980e341500f492425'

    # Random Generate.
    _words = mnemonic.generate()
    assert len(_words) == 12

    # Valid: True
    words = SENTENCE.split(' ')
    assert mnemonic.validate(words) == True

    # Valid: True
    assert mnemonic.validate(mnemonic.generate()) == True

    # Valid: False
    words2 = 'hello word'.split(' ')
    assert mnemonic.validate(words2) == False

    # Valid: False
    words3 = sorted(SENTENCE.split(' '))
    assert mnemonic.validate(words3) == False

    # Seed generated from words.
    assert mnemonic.derive_seed(words) == bytes.fromhex(SEED)

    # First Private Key generated from words.
    assert mnemonic.derive_private_key(words, 0) == bytes.fromhex(PRIV)


def test_keystore():
    ks = {
        "version": 3,
        "id": "f437ebb1-5b0d-4780-ae9e-8640178ffd77",
        "address": "dc6fa3ec1f3fde763f4d59230ed303f854968d26",
        "crypto":
        {
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": 32,
                "salt": "b57682e5468934be81217ad5b14ca74dab2b42c2476864592c9f3b370c09460a",
                "n": 262144,
                "r": 8,
                "p": 1
            },
            "cipher": "aes-128-ctr",
            "ciphertext": "88cb876f9c0355a89cad88ee7a17a2179700bc4306eaf78fa67320efbb4c7e31",
            "cipherparams": {
                "iv": "de5c0c09c882b3f679876b22b6c5af21"
            },
            "mac": "8426e8a1e151b28f694849cb31f64cbc9ae3e278d02716cf5b61d7ddd3f6e728"
        }
    }
    password = b'123456'
    private_key_hex = '1599403f7b6c17bb09f16e7f8ebe697af3626db5b41e0f9427a49151c6216920'

    _priv = keystore.decrypt(ks, password)
    assert _priv.hex() == private_key_hex


def test_hdnode():
    sentence = 'ignore empty bird silly journey junior ripple have guard waste between tenant'
    words = sentence.split(' ')

    addresses = [
        '339fb3c438606519e2c75bbf531fb43a0f449a70',
        '5677099d06bc72f9da1113afa5e022feec424c8e',
        '86231b5cdcbfe751b9ddcd4bd981fc0a48afe921',
        'd6f184944335f26ea59dbb603e38e2d434220fcd',
        '2ac1a0aecd5c80fb5524348130ab7cf92670470a'
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
        child_node = n.derive(idx)
        assert child_node.address().hex() == address
