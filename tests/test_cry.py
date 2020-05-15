from cry import black2b256
from cry import keccak256
from cry import is_address
from cry import to_checksum_address
from cry import public_key_to_address
from cry import secp256k1

def test_black2b():
    h, _ = black2b256([b'hello world'])
    assert h.hex() == '256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610'

    h, _ = black2b256([b'hello', b' world'])
    assert h.hex() == '256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610'

def test_keccak256():
    h, _ = keccak256([b'hello world'])
    assert h.hex() == '47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad'

    h, _ = keccak256([b'hello', b' world'])
    assert h.hex() == '47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad'

def test_address():
    address = [
        '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
        '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
        '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
        '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'
    ]

    for addr in address:
        assert is_address(addr)
        assert to_checksum_address(addr) == addr

def test_private_key():
    private_key = secp256k1.generate_privateKey()
    assert len(private_key) == 32

def test_derive_public_key():
    priv = bytes.fromhex('7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a')
    pub = bytes.fromhex('04b90e9bb2617387eba4502c730de65a33878ef384a46f1096d86f2da19043304afa67d0ad09cf2bea0c6f2d1767a9e62a7a7ecc41facf18f2fa505d92243a658f')
    _pub = secp256k1.derive_publicKey(priv)
    assert pub.hex() == _pub.hex()

def test_public_key_to_address():
    pub = bytes.fromhex('04b90e9bb2617387eba4502c730de65a33878ef384a46f1096d86f2da19043304afa67d0ad09cf2bea0c6f2d1767a9e62a7a7ecc41facf18f2fa505d92243a658f')
    address = public_key_to_address(pub)
    assert '0x' + address.hex() == '0xd989829d88b0ed1b06edf5c50174ecfa64f14a64'

def test_sign_hash():
    pub = bytes.fromhex('04b90e9bb2617387eba4502c730de65a33878ef384a46f1096d86f2da19043304afa67d0ad09cf2bea0c6f2d1767a9e62a7a7ecc41facf18f2fa505d92243a658f')
    priv = bytes.fromhex('7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a')
    msg_hash, _ = keccak256([b'hello world'])

    sig = secp256k1.sign(msg_hash, priv)
    assert sig.hex() == 'f8fe82c74f9e1f5bf443f8a7f8eb968140f554968fdcab0a6ffe904e451c8b9244be44bccb1feb34dd20d9d8943f8c131227e55861736907b02d32c06b934d7200'

    _pub = secp256k1.recover(msg_hash, sig)
    assert _pub.hex() == pub.hex()
