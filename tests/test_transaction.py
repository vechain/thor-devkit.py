import copy
import pytest
from thor_devkit import cry, transaction

dynamic_fee_transaction_body = {
  "id": '0xf47542ebf813c723fa087b342db4c5f67866cc1b03b362c37a1b1766cac5c53a',
  "type": 81,
  "chainTag": 228,
  "blockRef": '0x0001c400b93e3f87',
  "expiration": 30,
  "clauses": [
    {
      "to": '0x17c5fab5980157d0f2c14e1056e8ad828b43bb52',
      "value": '0x0',
      "data": '0xaecb29bf00000000000000000000000000000000000000000000000000000000000000977b7b81982ec56e3763f3a525d3675aacae0184a2fbeca967b8f5a979d6480e8a1c40ecc470246fba5958922b2554f93d946680a434f161b8e6cb5d63dfc1cdf5'
    }
  ],
  "gas": 946888,
  "maxFeePerGas": '0x33f2aa320fbd',
  "maxPriorityFeePerGas": '0x1f0',
  "origin": '0xa7d07b0176e8ec925f59bc3e75a4044f56991d3a',
  "nonce": 13214751594910995814,
  "size": 5150,
  "dependsOn": None,
  "meta": {
    "blockID": '0x0001c4016673373aac9a43f3730e32ef019ec22e055524f9417b2486ee958a57',
    "blockNumber": 115713,
    "blockTimestamp": 1748289731
  }
}

# Pre-galactica format (normal transaction)
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
    "nonce": 8
}

unsigned = transaction.Transaction(body)
unsigned_encoded = bytes.fromhex('f8510184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088008c0')

signed = transaction.Transaction(body)
signed_encoded = bytes.fromhex('f8940184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088008c0b84159a0d8ff585bb9e44b05e96859302d43d060fde2266db8e7c75ba1a9721001883aba41c2866aa69fab1099f6e31d2bee58a970074e02f89c6072b00d32cf2f2400')
priv_key = bytes.fromhex('7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a')
_a, _ = cry.blake2b256([signed.encode()])
_b = cry.secp256k1.sign(_a, priv_key)
signed.set_signature(_b)
signer = cry.public_key_to_address(cry.secp256k1.derive_publicKey(priv_key))


unsinged_dynamic_fee = transaction.Transaction(dynamic_fee_transaction_body)
unsinged_dynamic_fee_encoded = bytes.fromhex('f8a481e48701c400b93e3f871ef87ef87c9417c5fab5980157d0f2c14e1056e8ad828b43bb5280b864aecb29bf00000000000000000000000000000000000000000000000000000000000000977b7b81982ec56e3763f3a525d3675aacae0184a2fbeca967b8f5a979d6480e8a1c40ecc470246fba5958922b2554f93d946680a434f161b8e6cb5d63dfc1cdf58201f08633f2aa320fbd830e72c88088b7643a8f91b25566c0')

signed_dynamic_fee = transaction.Transaction(dynamic_fee_transaction_body)
signed_dynamic_fee_encoded = bytes.fromhex('f8e781e48701c400b93e3f871ef87ef87c9417c5fab5980157d0f2c14e1056e8ad828b43bb5280b864aecb29bf00000000000000000000000000000000000000000000000000000000000000977b7b81982ec56e3763f3a525d3675aacae0184a2fbeca967b8f5a979d6480e8a1c40ecc470246fba5958922b2554f93d946680a434f161b8e6cb5d63dfc1cdf58201f08633f2aa320fbd830e72c88088b7643a8f91b25566c0b841f720378109a9c077d85c041afa6e2f5b3ac08903fc5dcb0d3b337d77e91a4a7c27aa16974677ed6f24d76096291325614a54ab0f150821e3663562bb45e494f300')
message_hash = signed_dynamic_fee.get_signing_hash()
signed_dynamic_fee.set_signature(cry.secp256k1.sign(message_hash, priv_key))

def test_unsigned():
    x = unsigned.encode()
    signing_hash, _ = cry.blake2b256([x])
    assert signing_hash.hex() == '747453dfcba210d8bb4786c211a177909d109c87669bc0755fb25072a44150cf'

    assert unsigned.get_signing_hash().hex() == '747453dfcba210d8bb4786c211a177909d109c87669bc0755fb25072a44150cf'

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
    assert signed.get_signature().hex() == '59a0d8ff585bb9e44b05e96859302d43d060fde2266db8e7c75ba1a9721001883aba41c2866aa69fab1099f6e31d2bee58a970074e02f89c6072b00d32cf2f2400'
    assert signed.get_origin() == '0x' + signer.hex()
    assert signed.get_id() == '0x0d9e5937b4e9fa2d7284a9653c7f15417d3f71c9b4dd8bf51f2c88f5f99b0a8e'
    assert signed.get_signing_hash('0x' + signer.hex()).hex() == '0d9e5937b4e9fa2d7284a9653c7f15417d3f71c9b4dd8bf51f2c88f5f99b0a8e'
    assert signed.get_type() == transaction.TransactionType.NORMAL


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
    "size": 100,
    "gasPriceCoef": 128,
    "gas": 21000,
    "dependsOn": None,
    "nonce": 8,
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

def test_dynamic_fee_transaction():
    # Create a dynamic fee transaction
    tx = transaction.Transaction(dynamic_fee_transaction_body)
    
    assert tx.get_type() == transaction.TransactionType.DYNAMIC_FEE
    
    assert tx.get_max_fee_per_gas() == int('0x33f2aa320fbd', 16) 
    assert tx.get_max_priority_fee_per_gas() == int('0x1f0', 16) 
    
    assert 'gasPriceCoef' not in tx.get_body()
    
    assert tx.get_intrinsic_gas() > 0
    assert tx.get_max_fee_per_gas() == int('0x33f2aa320fbd', 16)
    assert tx.get_max_priority_fee_per_gas() == int('0x1f0', 16)
    
    body = tx.get_body()

def test_dynamic_fee_transaction_encoding():
    tx = transaction.Transaction(dynamic_fee_transaction_body)
    encoded = tx.encode()
    
    decoded = transaction.Transaction.decode(encoded, True)
    assert decoded.get_type() == transaction.TransactionType.DYNAMIC_FEE
    assert decoded.get_max_fee_per_gas() == tx.get_max_fee_per_gas()
    assert decoded.get_max_priority_fee_per_gas() == tx.get_max_priority_fee_per_gas()

def test_unsigned_transaction_type_detection():
    """Test that transaction type is correctly detected from RLP for unsigned transactions"""
    # Test normal transaction type detection
    normal_tx_type = transaction.Transaction.determine_transaction_type_from_rlp(unsigned_encoded)
    assert normal_tx_type == transaction.TransactionType.NORMAL
    
    # Test dynamic fee transaction type detection
    dynamic_fee_tx_type = transaction.Transaction.determine_transaction_type_from_rlp(unsinged_dynamic_fee_encoded)
    assert dynamic_fee_tx_type == transaction.TransactionType.DYNAMIC_FEE

def test_unsigned_transaction_roundtrip():
    """Test roundtrip encoding/decoding for unsigned transactions"""
    # Test normal transaction roundtrip
    normal_encoded = unsigned.encode()
    normal_decoded = transaction.Transaction.decode(normal_encoded, True)
    normal_re_encoded = normal_decoded.encode()
    assert normal_encoded.hex() == normal_re_encoded.hex()
    assert normal_decoded == unsigned
    
    # Test dynamic fee transaction roundtrip
    dynamic_fee_encoded = unsinged_dynamic_fee.encode()
    dynamic_fee_decoded = transaction.Transaction.decode(dynamic_fee_encoded, True)
    dynamic_fee_re_encoded = dynamic_fee_decoded.encode()
    assert dynamic_fee_encoded.hex() == dynamic_fee_re_encoded.hex()
    assert dynamic_fee_decoded == unsinged_dynamic_fee
