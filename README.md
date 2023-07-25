# VeChain Thor Devkit (SDK) in Python 3

Python 3 (Python 3.6+) library to assist smooth development on VeChain for developers and hobbyists.

|                          Content                          |
| --------------------------------------------------------- |
| Public key, private key, address conversion.              |
| Mnemonic Wallets.                                         |
| HD Wallet.                                                |
| Keystore.                                                 |
| Various Hashing functions.                                |
| Signing messages.                                         |
| Verify signature of messages.                             |
| Bloom filter.                                             |
| Transaction Assembling (**Multi-task Transaction, MTT**). |
| Fee Delegation Transaction (**VIP-191**).                 |
| Self-signed Certificate (**VIP-192**).                    |
| ABI decoding of "functions" and "events" in logs.         |

... and will always be updated with the **newest** features on VeChain.

# Install
```bash
pip3 install thor-devkit -U
```

***Caveat: Bip32 depends on the `ripemd160` hash library, which should be present on your system within OpenSSL.***

Type these in your terminal to see if they are available
```python
> python3
> import hashlib
> print('ripemd160' in hashlib.algorithms_available)
```

# Tutorials

### Private/Public Keys
```python
from thor_devkit import cry
from thor_devkit.cry import secp256k1

private_key = secp256k1.generate_privateKey()

public_key = secp256k1.derive_publicKey(private_key)

_address_bytes = cry.public_key_to_address(public_key)
address = '0x' + _address_bytes.hex()

print( address )
# 0x86d8cd908e43bc0076bc99e19e1a3c6221436ad0
print('is address?', cry.is_address(address))
# is address? True
print( cry.to_checksum_address(address) ) 
# 0x86d8CD908e43BC0076Bc99e19E1a3c6221436aD0
```

### Sign & Verify Signature

```python
from thor_devkit import cry
from thor_devkit.cry import secp256k1

# bytes
private_key = bytes.fromhex('7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a')
# bytes
msg_hash, _ = cry.keccak256([b'hello world'])

# Sign the message hash.
# bytes
signature = secp256k1.sign(msg_hash, private_key)

# Recover public key from given message hash and signature.
# bytes
public_key = secp256k1.recover(msg_hash, signature)
```

### Mnemonic Wallet

```python
from thor_devkit.cry import mnemonic

words = mnemonic.generate()
print(words)
# ['fashion', 'reduce', 'resource', 'ordinary', 'seek', 'kite', 'space', 'marriage', 'cube', 'detail', 'bundle', 'latin']

flag = mnemonic.validate(words)
print(flag)
# True

# Quickly get a Bip32 master seed for HD wallets. See below "HD Wallet".
seed = mnemonic.derive_seed(words)

# Quickly get a private key.
private_key = mnemonic.derive_private_key(words, 0)
```

### HD Wallet
Hierarchical Deterministic Wallets. See [bip-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) and [bip-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

```python
from thor_devkit import cry
from thor_devkit.cry import hdnode

# Construct an HD node from words. (Recommended)
words = 'ignore empty bird silly journey junior ripple have guard waste between tenant'.split(' ')

hd_node = cry.HDNode.from_mnemonic(
    words,
    init_path=hdnode.VET_EXTERNAL_PATH
) # VET wallet, you can input other string values to generate BTC/ETH/... wallets.

# Or, construct HD node from seed. (Advanced)
seed = '28bc19620b4fbb1f8892b9607f6e406fcd8226a0d6dc167ff677d122a1a64ef936101a644e6b447fd495677f68215d8522c893100d9010668614a68b3c7bb49f'

hd_node = cry.HDNode.from_seed(
    bytes.fromhex(seed),
    init_path=hdnode.VET_EXTERNAL_PATH
) # VET wallet, you can input other string values to generate BTC/ETH/... wallets.

# Access the HD node's properties.
priv = hd_node.private_key()
pub = hd_node.public_key()
addr = hd_node.address()
cc = hd_node.chain_code()

# Or, construct HD node from a given public key. (Advanced)
# Notice: This HD node cannot derive child HD node with "private key".
hd_node = cry.HDNode.from_public_key(pub, cc)

# Or, construct HD node from a given private key. (Advanced)
hd_node = cry.HDNode.from_private_key(priv, cc)

# Let it derive further child HD nodes.
for i in range(0, 3):
    print('addr:', '0x'+hd_node.derive(i).address().hex())
    print('priv:', hd_node.derive(i).private_key().hex())

# addr: 0x339fb3c438606519e2c75bbf531fb43a0f449a70
# priv: 27196338e7d0b5e7bf1be1c0327c53a244a18ef0b102976980e341500f492425
# addr: 0x5677099d06bc72f9da1113afa5e022feec424c8e
# priv: 0xcf44074ec3bf912d2a46b7c84fa6eb745652c9c74e674c3760dc7af07fc98b62
# addr: 0x86231b5cdcbfe751b9ddcd4bd981fc0a48afe921
# priv: 2ca054a50b53299ea3949f5362ee1d1cfe6252fbe30bea3651774790983e9348
```

### Keystore

```python
from thor_devkit.cry import keystore

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

# Decrypt
private_key = keystore.decrypt(ks, password)

# Encrypt
ks_backup = keystore.encrypt(private_key, password)
```

### Hash the Messages
```python
from thor_devkit import cry

result, length = cry.blake2b256([b'hello world'])
result2, length = cry.blake2b256([b'hello', b' world'])
# result == result2

result, length = cry.keccak256([b'hello world'])
result2, length = cry.keccak256([b'hello', b' world'])
# result == result2
```


### Bloom Filter
```python
from thor_devkit import Bloom

# Create a bloom filter that can store 100 items.
_k = Bloom.estimate_k(100)
b = Bloom(_k)

# Add an item to the bloom filter.
b.add(bytes('hello world', 'UTF-8'))

# Verify
b.test(bytes('hello world', 'UTF-8'))
# True
b.test(bytes('bye bye blue bird', 'UTF-8'))
# False
```

### Transaction

```python
from thor_devkit import cry, transaction

# See: https://docs.vechain.org/thor/learn/transaction-model.html#model
body = {
    "chainTag": int('0x4a', 16), # 0x4a/0x27/0xa4 See: https://docs.vechain.org/others/miscellaneous.html#network-identifier
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

# Construct an unsigned transaction.
tx = transaction.Transaction(body)

# Access its properties.
tx.get_signing_hash() == cry.blake2b256([tx.encode()])[0] # True

tx.get_signature() == None # True

tx.get_origin() == None # True

tx.get_intrinsic_gas() == 37432 # estimate the gas this tx gonna cost.

# Sign the transaction with a private key.
priv_key = bytes.fromhex('7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a')
message_hash = tx.get_signing_hash()
signature = cry.secp256k1.sign(message_hash, priv_key)

# Set the signature on the transaction.
tx.set_signature(signature)

# Tx origin?
print(tx.get_origin())
# 0xd989829d88b0ed1b06edf5c50174ecfa64f14a64

# Tx id?
print(tx.get_id())
# 0xda90eaea52980bc4bb8d40cb2ff84d78433b3b4a6e7d50b75736c5e3e77b71ec

# Tx encoded into bytes, ready to be sent out.
encoded_bytes = tx.encode()

# pretty print the encoded bytes.
print('0x' + encoded_bytes.hex())

# http POST transaction to send the encoded_bytes to VeChain...
# See the REST API details:
# testnet: https://sync-testnet.vechain.org/doc/swagger-ui/
# mainnet: https://sync-mainnet.vechain.org/doc/swagger-ui/
```

### Transaction (VIP-191)
[https://github.com/vechain/VIPs/blob/master/vips/VIP-191.md](https://github.com/vechain/VIPs/blob/master/vips/VIP-191.md)

```python
from thor_devkit import cry, transaction

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
        "features": 1
    }
}

delegated_tx = transaction.Transaction(delegated_body)

# Indicate it is a delegated Transaction using VIP-191.
assert delegated_tx.is_delegated() == True

# Sender
addr_1 = '0xf9ea4ba688d55cc7f0eae0dd62f8271b744637bf'

priv_1 = bytes.fromhex('58e444d4fe08b0f4d9d86ec42f26cf15072af3ddc29a78e33b0ceaaa292bcf6b')


# Gas Payer
addr_2 = '0x34b7538c2a7c213dd34c3ecc0098097d03a94dcb'

priv_2 = bytes.fromhex('0bfd6a863f347f4ef2cf2d09c3db7b343d84bb3e6fc8c201afee62de6381dc65')


h = delegated_tx.get_signing_hash() # Sender hash to be signed.
dh = delegated_tx.get_signing_hash(addr_1) # Gas Payer hash to be signed.

# Sender sign the hash.
# Gas payer sign the hash.
# Concat two parts to forge a legal signature.
sig = cry.secp256k1.sign(h, priv_1) + cry.secp256k1.sign(dh, priv_2)

delegated_tx.set_signature(sig)

assert delegated_tx.get_origin() == addr_1
assert delegated_tx.get_delegator() == addr_2
```

### Sign/Verify Certificate (VIP-192)
[https://github.com/vechain/VIPs/blob/master/vips/VIP-192.md](https://github.com/vechain/VIPs/blob/master/vips/VIP-192.md)

```python
from thor_devkit import cry
from thor_devkit.cry import secp256k1
from thor_devkit import certificate

# My address.
address = '0xd989829d88b0ed1b06edf5c50174ecfa64f14a64'
# My corresponding private key.
private_key = bytes.fromhex('7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a')

# My cert.
cert_dict = {
    'purpose': 'identification',
    'payload': {
        'type': 'text',
        'content': 'fyi'
    },
    'domain': 'localhost',
    'timestamp': 1545035330,
    'signer': address
}

# Construct a cert, without signature.
cert = certificate.Certificate(**cert_dict)

# Sign the cert with my private key.
sig_bytes = secp256k1.sign(
    cry.blake2b256([
        certificate.encode(cert).encode('utf-8')
    ])[0],
    private_key
)
signature = '0x' + sig_bytes.hex()

# Mount the signature onto the cert.
cert_dict['signature'] = signature

# Construct a cert, with signature.
cert2 = certificate.Certificate(**cert_dict)

# Verify, if verify failed it will throw Exceptions.
certificate.verify(cert2)
```

### ABI

Encode function name and parameters according to ABI.

```python
from thor_devkit import abi

abi_dict = {
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
}

# Verify if abi_dict is in good shape.
f1 = abi.FUNCTION(abi_dict)

# Get a function instance of the abi.
f = abi.Function(f1)

# Get function selector:
selector = f.selector.hex()
selector == '27fcbb2f'

# Encode the function input parameters.
r = f.encode([1, 'foo'], to_hex=True)
r == '0x27fcbb2f000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000003666f6f0000000000000000000000000000000000000000000000000000000000'

# Decode function return result according to abi.
data = '000000000000000000000000abc000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000003666f6f0000000000000000000000000000000000000000000000000000000000'

r = f.decode(bytes.fromhex(data))
# {
#     "0": '0xabc0000000000000000000000000000000000001',
#     "1": b'666f6f',
#     "r1": '0xabc0000000000000000000000000000000000001',
#     "r2": b'666f6f'
# }
```

Decode logs according to data and topics.

```python
from thor_devkit import abi

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

ee = abi.Event(e2)

# data in hex format.
r = ee.decode(
    data=bytes.fromhex('00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003666f6f0000000000000000000000000000000000000000000000000000000000'),
    topics=[
        bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
    ]
)

# r == { "0": 1, "1": "foo", "a1": 1, "a2": "foo" }
```

# Tweak the Code

## Layout
```
.
├── LICENSE
├── README.md
├── requirements.txt
└── thor_devkit
    ├── __init__.py
    ├── abi.py
    ├── bloom.py
    ├── certificate.py
    ├── cry
    │   ├── __init__.py
    │   ├── address.py
    │   ├── blake2b.py
    │   ├── hdnode.py
    │   ├── keccak.py
    │   ├── keystore.py
    │   ├── mnemonic.py
    │   ├── secp256k1.py
    │   └── utils.py
    ├── rlp.py
    └── transaction.py
```

## Local Development
```bash
# install dependencies
make install
# test code
make test
```

## Knowledge

|     Name     | Bytes |                  Description                   |
| ------------ | ----- | ---------------------------------------------- |
| private key  | 32    | random number                                  |
| public key   | 65    | uncompressed, starts with "04"                 |
| address      | 20    | derived from public key                        |
| keccak256    | 32    | hash                                           |
| blake2b256   | 32    | hash                                           |
| message hash | 32    | hash of a message                              |
| signature    | 65    | signing result, last bit as recovery parameter |
| seed         | 64    | used to derive bip32 master key                |
