import copy
import pytest
from thor_devkit import cry, transaction

body = {
    "chainTag": 1,
    "blockRef": '0x00000000aabbccdd',
    "expiration": 32,
    "clauses": [
        {
            "to": '0x7567d83b7b8d80addcb281a71d54fc7b3364ffed',
            "value": 10000,
            "data": '0x000000606060'
        },
        {
            "to": '0x7567d83b7b8d80addcb281a71d54fc7b3364ffed',
            "value": 20000,
            "data": '0x000000606060'
        }
    ],
    "gasPriceCoef": 128,
    "gas": 21000,
    "dependsOn": None,
    "nonce": 12345678
}

unsigned = transaction.Transaction(body)
unsigned_encoded = bytes.fromhex('f8540184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088083bc614ec0')

signed = transaction.Transaction(body)
signed_encoded = bytes.fromhex('f8970184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088083bc614ec0b841f76f3c91a834165872aa9464fc55b03a13f46ea8d3b858e528fcceaf371ad6884193c3f313ff8effbb57fe4d1adc13dceb933bedbf9dbb528d2936203d5511df00')
priv_key = bytes.fromhex('7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a')
_a, _ = cry.blake2b256([signed.encode()])
_b = cry.secp256k1.sign(_a, priv_key)
signed.set_signature(_b)
signer = cry.public_key_to_address(cry.secp256k1.derive_publicKey(priv_key))

def test_unsigned():
    x = unsigned.encode()
    signing_hash, _ = cry.blake2b256([x])
    assert signing_hash.hex() == '2a1c25ce0d66f45276a5f308b99bf410e2fc7d5b6ea37a49f2ab9f1da9446478'

    assert unsigned.get_signing_hash().hex() == '2a1c25ce0d66f45276a5f308b99bf410e2fc7d5b6ea37a49f2ab9f1da9446478'

    assert unsigned.get_id() is None

    assert unsigned.get_intrinsic_gas() == 37432

    assert unsigned.get_signature() == None

    assert unsigned.get_origin() == None

    assert unsigned.encode().hex() == unsigned_encoded.hex()

    assert transaction.Transaction.decode(unsigned_encoded, True) == unsigned

    body_1 = copy.deepcopy(body)
    body_1['clauses'] = []

    assert transaction.Transaction(body_1).get_intrinsic_gas() == 21000

    body_2 = copy.deepcopy(body)
    body_2['clauses'] = [
        {
            "to": None,
            "value": 0,
            "data": '0x'
        }
    ]

    assert transaction.Transaction(body_2).get_intrinsic_gas() == 53000


def test_empty_data():
    body_1 = copy.deepcopy(body)
    body_1['clauses'][0]['data'] = '0x'
    transaction.Transaction(body_1).encode()


def test_invalid_body():
    with pytest.raises(Exception):
        body_1 = copy.deepcopy(body)
        body_1["chainTag"] = 256
        transaction.Transaction(body_1).encode()
    
    with pytest.raises(Exception):
        body_1 = copy.deepcopy(body)
        body_1["chainTag"] = -1
        transaction.Transaction(body_1).encode()
    
    with pytest.raises(Exception):
        body_1 = copy.deepcopy(body)
        body_1["chainTag"] = 1.1
        transaction.Transaction(body_1).encode()
    
    with pytest.raises(Exception):
        body_1 = copy.deepcopy(body)
        body_1['blockRef'] = '0x'
        transaction.Transaction(body_1).encode()
    
    with pytest.raises(Exception):
        body_1 = copy.deepcopy(body)
        body_1['blockRef'] = '0x' + '0' * 18
        transaction.Transaction(body_1).encode()
    
    with pytest.raises(Exception):
        body_1 = copy.deepcopy(body)
        body_1['expiration'] = 2 ** 32
        transaction.Transaction(body_1).encode()
    
    with pytest.raises(Exception):
        body_1 = copy.deepcopy(body)
        body_1['expiration'] = -1
        transaction.Transaction(body_1).encode()
    
    with pytest.raises(Exception):
        body_1 = copy.deepcopy(body)
        body_1['expiration'] = 1.1
        transaction.Transaction(body_1).encode()

    with pytest.raises(Exception):
        body_1 = copy.deepcopy(body)
        body_1['gasPriceCoef'] = 256
        transaction.Transaction(body_1).encode()
    
    with pytest.raises(Exception):
        body_1 = copy.deepcopy(body)
        body_1['gasPriceCoef'] = -1
        transaction.Transaction(body_1).encode()

    with pytest.raises(Exception):
        body_1 = copy.deepcopy(body)
        body_1['gasPriceCoef'] = 1.1
        transaction.Transaction(body_1).encode()

    with pytest.raises(Exception):
        body_1 = copy.deepcopy(body)
        body_1['gas'] = '0x10000000000000000'
        transaction.Transaction(body_1).encode()
    
    with pytest.raises(Exception):
        body_1 = copy.deepcopy(body)
        body_1['nonce'] = '0x10000000000000000'
        transaction.Transaction(body_1).encode()

def test_signed():
    assert signed.get_signature().hex() == 'f76f3c91a834165872aa9464fc55b03a13f46ea8d3b858e528fcceaf371ad6884193c3f313ff8effbb57fe4d1adc13dceb933bedbf9dbb528d2936203d5511df00'
    assert signed.get_origin() == '0x' + signer.hex()
    assert signed.get_id() == '0xda90eaea52980bc4bb8d40cb2ff84d78433b3b4a6e7d50b75736c5e3e77b71ec'
    assert signed.get_signing_hash('0x' + signer.hex()).hex() == 'da90eaea52980bc4bb8d40cb2ff84d78433b3b4a6e7d50b75736c5e3e77b71ec'

def test_encode_decode():
    assert signed.encode().hex() == signed_encoded.hex()
    assert transaction.Transaction.decode(signed_encoded, False) == signed

    with pytest.raises(Exception):
        transaction.Transaction.decode(unsigned_encoded, False)
    
    # TODO
    # with pytest.raises(Exception):
    #     transaction.Transaction.decode(signed_encoded, True)

def test_incorrectly_signed():
    tx = transaction.Transaction(body)
    tx.set_signature(bytes([1,2,3]))
    assert tx.get_origin() == None
    assert tx.get_id() == None

delegated_body = {
    "chainTag": 1,
    "blockRef": '0x00000000aabbccdd',
    "expiration": 32,
    "clauses": [
        {
            "to": '0x7567d83b7b8d80addcb281a71d54fc7b3364ffed',
            "value": 10000,
            "data": '0x000000606060'
        },
        {
            "to": '0x7567d83b7b8d80addcb281a71d54fc7b3364ffed',
            "value": 20000,
            "data": '0x000000606060'
        }
    ],
    "gasPriceCoef": 128,
    "gas": 21000,
    "dependsOn": None,
    "nonce": 12345678,
    "reserved": {
        "features": 1,
        "unused": [b'1234']
    }
}

delegated_tx = transaction.Transaction(copy.deepcopy(delegated_body))

def test_features():
    assert unsigned.is_delegated() == False
    assert delegated_tx.is_delegated() == True

    # Sender
    # priv_1 = cry.secp256k1.generate_privateKey()
    priv_1 = bytes.fromhex('58e444d4fe08b0f4d9d86ec42f26cf15072af3ddc29a78e33b0ceaaa292bcf6b')
    addr_1 = cry.public_key_to_address( cry.secp256k1.derive_publicKey(priv_1) )

    # Gas payer
    # priv_2 = cry.secp256k1.generate_privateKey()
    priv_2 = bytes.fromhex('0bfd6a863f347f4ef2cf2d09c3db7b343d84bb3e6fc8c201afee62de6381dc65')
    addr_2 = cry.public_key_to_address( cry.secp256k1.derive_publicKey(priv_2) )

    h = delegated_tx.get_signing_hash()
    dh = delegated_tx.get_signing_hash('0x' + addr_1.hex())

    # Concat two parts to forge a signature.
    sig = cry.secp256k1.sign(h, priv_1) + cry.secp256k1.sign(dh, priv_2)

    delegated_tx.set_signature(sig)

    assert delegated_tx.get_origin() == '0x' + addr_1.hex()
    assert delegated_tx.get_delegator() == '0x' + addr_2.hex()

# Well this is a dangerous part, we tests the "private" function.
# Shouldn't recommend you to do the same, but I need to test it.
def test_unused():
    delegated_body_2 = copy.deepcopy(delegated_body)
    delegated_body_2["reserved"]["unused"] = [bytes.fromhex("0F0F"), bytes.fromhex("0101")]
    delegated_tx_2 = transaction.Transaction(delegated_body_2)
    assert delegated_tx_2.is_delegated() == True
    assert transaction.Transaction.decode(delegated_tx_2.encode(), True) == delegated_tx_2

    reserved_list = delegated_tx_2._encode_reserved()
    assert reserved_list == [bytes.fromhex("01"), bytes.fromhex("0F0F"), bytes.fromhex("0101")]

    delegated_body_3 = copy.deepcopy(delegated_body)
    delegated_body_3["reserved"]["unused"] = [bytes.fromhex("0F0F"), bytes(0)]
    delegated_tx_3 = transaction.Transaction(delegated_body_3)
    assert delegated_tx_3.is_delegated() == True

    reserved_list = delegated_tx_3._encode_reserved()
    assert reserved_list == [bytes.fromhex("01"), bytes.fromhex("0F0F")]
    assert transaction.Transaction.decode(delegated_tx_3.encode(), True) == delegated_tx_3

def test_body_copy():
    b1 = copy.deepcopy(body)
    tx = transaction.Transaction(b1)
    b2 = tx.get_body(False)
    b3 = tx.get_body(True)

    assert id(b2) != id(b3) # id should be different
    assert b2 == b3 # content should be the same