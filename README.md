<!-- FIXME: Change RTD link here and in first section after RTD are published -->
[![PyPi Version](https://img.shields.io/pypi/v/thor_devkit.svg)](https://pypi.python.org/pypi/thor_devkit/)
[![Python Versions](https://img.shields.io/pypi/pyversions/thor_devkit.svg)](https://pypi.python.org/pypi/thor_devkit/)
[![Read the Docs](https://readthedocs.org/projects/thor-devkitpy-alt/badge/?version=latest)](https://thor-devkitpy-alt.readthedocs.io/en/latest/?badge=latest)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# VeChain Thor Devkit (SDK) in Python 3

Python 3 (``Python 3.6+``) library to assist smooth development on VeChain for developers and hobbyists.

- [VeChain Thor Devkit (SDK) in Python 3](#vechain-thor-devkit--sdk--in-python-3)
- [Install](#install)
- [Tutorials](#tutorials)
    + [Validation](#validation)
    + [Private/Public Keys](#private-public-keys)
    + [Sign & Verify Signature](#sign---verify-signature)
    + [Mnemonic Wallet](#mnemonic-wallet)
    + [HD Wallet](#hd-wallet)
    + [Keystore](#keystore)
    + [Hash the Messages](#hash-the-messages)
    + [Bloom Filter](#bloom-filter)
    + [Transaction](#transaction)
    + [Transaction (VIP-191)](#transaction--vip-191-)
    + [Sign/Verify Certificate (VIP-192)](#sign-verify-certificate--vip-192-)
    + [ABI](#abi)
- [Tweak the Code](#tweak-the-code)
  * [Layout](#layout)
  * [Local Development](#local-development)
  * [Knowledge](#knowledge)
  * [Upgrading to version 2.0.0](#upgrading-to-version-200)

... and will always be updated with the **newest** features on VeChain.

Read our [documentation](https://thor-devkitpy-alt.readthedocs.io/en/latest/) on ReadTheDocs.

# Install

```bash
pip3 install thor-devkit -U
```

***Caveat: Bip32 depends on the ripemd160 hash library, which should be present on your system.***

Supported extras:

- `test`: install developer requirements (`pip install thor-devkit[test]`).
- `docs`: install `sphinx`-related packages (`pip install thor-devkit[test,docs]`).

# Tutorials

### Validation

Many modules and classes have `validate` and `is_valid` methods. They perform exactly the same validation, but the former raises exceptions for malformed inputs (returns `True` for valid), while the latter returns `False` for invalid and `True` for valid inputs.

### Private/Public Keys

```pycon
>>> from thor_devkit import cry
>>> from thor_devkit.cry import secp256k1
>>> private_key = secp256k1.generate_private_key()
>>> public_key = secp256k1.derive_public_key(private_key)
>>> _address_bytes = cry.public_key_to_address(public_key)
>>> address = '0x' + _address_bytes.hex()
>>> address  # doctest:+SKIP
'0x86d8cd908e43bc0076bc99e19e1a3c6221436ad0'
>>> cry.is_address(address)  # Is it a valid address?
True
>>> cry.to_checksum_address(address)  # doctest:+SKIP
'0x86d8CD908e43BC0076Bc99e19E1a3c6221436aD0'
```

### Sign & Verify Signature

```pycon
>>> from thor_devkit.cry import secp256k1, keccak256
>>> private_key = bytes.fromhex(
...     '7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a'
... )  # bytes
>>> msg_hash, _ = keccak256([b'hello world'])  # bytes

Sign the message hash:
>>> signature = secp256k1.sign(msg_hash, private_key)  # bytes

Recover public key from given message hash and signature:
>>> public_key = secp256k1.recover(msg_hash, signature)  # bytes

```

### Mnemonic Wallet

```pycon
>>> from thor_devkit.cry import mnemonic
>>> words = mnemonic.generate()
>>> words  # doctest:+SKIP
['fashion', 'reduce', 'resource', 'ordinary', 'seek', 'kite', 'space', 'marriage', 'cube', 'detail', 'bundle', 'latin']
>>> assert mnemonic.is_valid(words)

Quickly get a Bip32 master seed for HD wallets. See below "HD Wallet".
>>> seed = mnemonic.derive_seed(words)

Quickly get a private key:
>>> private_key = mnemonic.derive_private_key(words, 0)

```

### HD Wallet

Hierarchical Deterministic Wallets.

See [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) and [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

```pycon
>>> from thor_devkit.cry import hdnode, HDNode

Construct an HD node from words (recommended):
>>> words = 'ignore empty bird silly journey junior ripple have guard waste between tenant'.split()

>>> hd_node = HDNode.from_mnemonic(
...     words,
...     init_path=hdnode.VET_EXTERNAL_PATH,
... ) # VET wallet, you can input other string values to generate BTC/ETH/... wallets.

Or, construct HD node from seed (advanced):
>>> seed = '28bc19620b4fbb1f8892b9607f6e406fcd8226a0d6dc167ff677d122a1a64ef936101a644e6b447fd495677f68215d8522c893100d9010668614a68b3c7bb49f'
>>> hd_node = HDNode.from_seed(
...     bytes.fromhex(seed),
...     init_path=hdnode.VET_EXTERNAL_PATH,
... ) # VET wallet, you can input other string values to generate BTC/ETH/... wallets.

Access the HD node's properties:
>>> priv = hd_node.private_key
>>> pub = hd_node.public_key
>>> addr = hd_node.address
>>> cc = hd_node.chain_code

Or, construct HD node from a given public key (advanced)
Notice: This HD node cannot derive child HD node with "private key".
>>> hd_node = HDNode.from_public_key(pub, cc)

Or, construct HD node from a given private key (advanced):
>>> hd_node = HDNode.from_private_key(priv, cc)

Let it derive further child HD nodes:
>>> for i in range(3):
...     print('addr:', '0x' + hd_node.derive(i).address.hex())
...     print('priv:', hd_node.derive(i).private_key.hex())
addr: 0x339fb3c438606519e2c75bbf531fb43a0f449a70
priv: 27196338e7d0b5e7bf1be1c0327c53a244a18ef0b102976980e341500f492425
addr: 0x5677099d06bc72f9da1113afa5e022feec424c8e
priv: cf44074ec3bf912d2a46b7c84fa6eb745652c9c74e674c3760dc7af07fc98b62
addr: 0x86231b5cdcbfe751b9ddcd4bd981fc0a48afe921
priv: 2ca054a50b53299ea3949f5362ee1d1cfe6252fbe30bea3651774790983e9348

```

### Keystore

```pycon
>>> from thor_devkit.cry import keystore
>>> ks = {
...     "version": 3,
...     "id": "f437ebb1-5b0d-4780-ae9e-8640178ffd77",
...     "address": "dc6fa3ec1f3fde763f4d59230ed303f854968d26",
...     "crypto":
...     {
...         "kdf": "scrypt",
...         "kdfparams": {
...             "dklen": 32,
...             "salt": "b57682e5468934be81217ad5b14ca74dab2b42c2476864592c9f3b370c09460a",
...             "n": 262144,
...             "r": 8,
...             "p": 1
...         },
...         "cipher": "aes-128-ctr",
...         "ciphertext": "88cb876f9c0355a89cad88ee7a17a2179700bc4306eaf78fa67320efbb4c7e31",
...         "cipherparams": {
...             "iv": "de5c0c09c882b3f679876b22b6c5af21"
...         },
...         "mac": "8426e8a1e151b28f694849cb31f64cbc9ae3e278d02716cf5b61d7ddd3f6e728"
...     }
... }
>>> password = b'123456'

Decrypt:
>>> private_key = keystore.decrypt(ks, password)

Encrypt:
>>> ks_backup = keystore.encrypt(private_key, password)

```

### Hash the Messages

```pycon
>>> from thor_devkit.cry import blake2b256, keccak256

>>> result, length = blake2b256([b'hello world'])
>>> result2, length = blake2b256([b'hello', b' world'])
>>> assert result == result2
>>> result.hex()
'256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610'
>>> result, length = keccak256([b'hello world'])
>>> result2, length = keccak256([b'hello', b' world'])
>>> assert result == result2
>>> result.hex()
'47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad'

```


### Bloom Filter

```pycon
>>> from thor_devkit import Bloom

Create a bloom filter that can store 100 items:
>>> _k = Bloom.estimate_k(100)
>>> _k
14
>>> b = Bloom(_k)

Add an item to the bloom filter:
>>> b.add(b'hello world')
True

Verify:
>>> assert b'hello world' in b
>>> assert b'bye bye blue bird' not in b

```

### Transaction

[Docs](https://docs.vechain.org/thor/learn/transaction-model.html#model)

[`chainTag` explained](https://docs.vechain.org/others/miscellaneous.html#network-identifier)

See the VeChain net REST API details (e.g. post transaction):
[testnet](https://sync-testnet.vechain.org/doc/swagger-ui/),
[mainnet](https://sync-mainnet.vechain.org/doc/swagger-ui/)

```pycon
>>> from thor_devkit import cry
>>> from thor_devkit.transaction import Transaction
>>> body = {
...     "chainTag": int('0x4a', 16), # 0x4a/0x27/0xa4
...     "blockRef": '0x00000000aabbccdd',
...     "expiration": 32,
...     "clauses": [
...         {
...             "to": '0x7567d83b7b8d80addcb281a71d54fc7b3364ffed',
...             "value": 10000,
...             "data": '0x000000606060'
...         },
...         {
...             "to": '0x7567d83b7b8d80addcb281a71d54fc7b3364ffed',
...             "value": 20000,
...             "data": '0x000000606060'
...         }
...     ],
...     "gasPriceCoef": 128,
...     "gas": 21000,
...     "dependsOn": None,
...     "nonce": 12345678
... }

Construct an unsigned transaction:
>>> tx = Transaction(body)

Access its properties:
>>> assert tx.get_signing_hash() == cry.blake2b256([tx.encode()])[0]
>>> assert tx.signature is None
>>> assert tx.origin is None
>>> assert tx.intrinsic_gas == 37432 # estimate the gas this tx gonna cost.

Sign the transaction with a private key:
>>> priv_key = bytes.fromhex(
...     '7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a'
... )
>>> message_hash = tx.get_signing_hash()
>>> signature = cry.secp256k1.sign(message_hash, priv_key)
>>> tx.signature = signature

>>> tx.origin
'0xd989829d88b0ed1b06edf5c50174ecfa64f14a64'
>>> tx.id
'0xf2c89da3d85952e99961d409abb0b2afb7fa266acc5ed23fb5d23a5d3db395d7'

Tx encoded into bytes, ready to be sent out:
>>> "0x" + tx.encode().hex()
'0xf8974a84aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088083bc614ec0b8419d500064647f37254e22b3ffac04bb5ccff5d91b6d6103a53baeedac17708b8817c6137e1efe3472f3b6fd8af258c2c3945b742c58ba49de2796c8bb54a0bb0601'

```

### Transaction (VIP-191)

See [VIP-191](https://github.com/vechain/VIPs/blob/master/vips/VIP-191.md) for reference.

```pycon
>>> from thor_devkit.cry import secp256k1
>>> from thor_devkit.transaction import Transaction
>>> delegated_body = {
...     "chainTag": 1,
...     "blockRef": '0x00000000aabbccdd',
...     "expiration": 32,
...     "clauses": [
...         {
...             "to": '0x7567d83b7b8d80addcb281a71d54fc7b3364ffed',
...             "value": 10000,
...             "data": '0x000000606060'
...         },
...         {
...             "to": '0x7567d83b7b8d80addcb281a71d54fc7b3364ffed',
...             "value": 20000,
...             "data": '0x000000606060'
...         }
...     ],
...     "gasPriceCoef": 128,
...     "gas": 21000,
...     "dependsOn": None,
...     "nonce": 12345678,
...     "reserved": {
...         "features": 1
...     }
... }
>>> delegated_tx = Transaction(delegated_body)

Indicate it is a delegated Transaction using VIP-191.
>>> assert delegated_tx.is_delegated

Sender:
>>> addr_1 = '0xf9ea4ba688d55cc7f0eae0dd62f8271b744637bf'
>>> priv_1 = bytes.fromhex('58e444d4fe08b0f4d9d86ec42f26cf15072af3ddc29a78e33b0ceaaa292bcf6b')

Gas Payer:
>>> addr_2 = '0x34b7538c2a7c213dd34c3ecc0098097d03a94dcb'
>>> priv_2 = bytes.fromhex('0bfd6a863f347f4ef2cf2d09c3db7b343d84bb3e6fc8c201afee62de6381dc65')

>>> h = delegated_tx.get_signing_hash() # Sender hash to be signed.
>>> dh = delegated_tx.get_signing_hash(addr_1) # Gas Payer hash to be signed.

Sender signs the hash.
Gas payer signs the hash.
Concatenate two parts to forge a legal signature:
>>> sig = secp256k1.sign(h, priv_1) + secp256k1.sign(dh, priv_2)
>>> delegated_tx.signature = sig

>>> assert delegated_tx.origin == addr_1
>>> assert delegated_tx.delegator == addr_2

```

### Sign/Verify Certificate (VIP-192)

[https://github.com/vechain/VIPs/blob/master/vips/VIP-192.md](https://github.com/vechain/VIPs/blob/master/vips/VIP-192.md)

```pycon
>>> from thor_devkit.cry import secp256k1
>>> from thor_devkit.certificate import Certificate

My private key and address:
>>> address = '0xd989829d88b0ed1b06edf5c50174ecfa64f14a64'
>>> private_key = bytes.fromhex(
...     '7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a'
... )

My certificate data:
>>> cert_dict = {
...     'purpose': 'identification',
...     'payload': {
...         'type': 'text',
...         'content': 'fyi',
...     },
...     'domain': 'localhost',
...     'timestamp': 1545035330,
...     'signer': address,
... }

Construct a certificate without signature:
>>> cert = Certificate(**cert_dict)

Sign the certificate with my private key:
>>> sig_bytes = secp256k1.sign(
...     cry.blake2b256([
...         cert.encode().encode()  # encode to string, then string to bytes.
...     ])[0],
...     private_key
... )
>>> signature = '0x' + sig_bytes.hex()

Construct a certificate with signature:
>>> cert_dict['signature'] = signature
>>> cert2 = Certificate(**cert_dict)

Verify, if verify failed it will throw Exceptions.
>>> cert2.verify()
True

Or get boolean validness:
>>> assert cert2.is_valid()

```

### ABI

Encode function name and parameters according to ABI.

```pycon
>>> from pprint import pprint
>>> from thor_devkit.abi import Function
>>> abi_dict = {
...     "inputs": [
...         {
...             "name": "a1",
...             "type": "uint256"
...         },
...         {
...             "name": "a2",
...             "type": "string"
...         }
...     ],
...     "name": "f1",
...     "outputs": [
...         {
...             "name": "r1",
...             "type": "address"
...         },
...         {
...             "name": "r2",
...             "type": "bytes"
...         }
...     ],
...     "stateMutability": "nonpayable",
...     "type": "function"
... }

Create a function instance of the ABI:
>>> f = Function(abi_dict)

Get function selector:
>>> f.selector.hex()
'27fcbb2f'

Encode the function input parameters:
>>> f.encode([1, 'foo'], to_hex=True)
'0x27fcbb2f000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000003666f6f0000000000000000000000000000000000000000000000000000000000'

Decode function return result according to ABI:
>>> data = '000000000000000000000000abc000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000003666f6f0000000000000000000000000000000000000000000000000000000000'

>>> result = f.decode(bytes.fromhex(data))
>>> result.to_dict()  # Use dictionary form
{'r1': '0xabc0000000000000000000000000000000000001', 'r2': b'foo'}
>>> assert result[0] == '0xabc0000000000000000000000000000000000001'   # Access by index
>>> assert result.r2 == b'foo'  # Or by name

Create function from solidity code:
>>> contract = '''
... contract A {
...     function f(uint x) public returns(bool) {}
... }
... '''
>>> func = Function.from_solidity(text=contract)
>>> pprint(func._definition)
{'inputs': [{'internalType': 'uint256', 'name': 'x', 'type': 'uint256'}],
 'name': 'f',
 'outputs': [{'internalType': 'bool', 'name': '', 'type': 'bool'}],
 'stateMutability': 'nonpayable',
 'type': 'function'}

```

Decode logs according to data and topics.

```pycon
>>> from thor_devkit.abi import Event
>>> data = {
...     "anonymous": True,
...     "inputs": [
...         {
...             "indexed": True,
...             "name": "a1",
...             "type": "uint256"
...         },
...         {
...             "indexed": False,
...             "name": "a2",
...             "type": "string"
...         }
...     ],
...     "name": "E2",
...     "type": "event"
... }
>>> event = Event(data)

Decode data in hex format:
>>> result = event.decode(
...     data=bytes.fromhex('00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003666f6f0000000000000000000000000000000000000000000000000000000000'),
...     topics=[
...         bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
...     ]
... )
>>> result.to_dict()
{'a1': 1, 'a2': 'foo'}
>>> result[0]
1
>>> result.a2
'foo'

Create event from solidity code:
>>> contract = '''
... contract A {
...     event E(uint indexed a1, string a2) anonymous;
... }
... '''
>>> func = Event.from_solidity(text=contract)
>>> pprint(func._definition)
{'anonymous': True,
 'inputs': [{'indexed': True,
             'internalType': 'uint256',
             'name': 'a1',
             'type': 'uint256'},
            {'indexed': False,
             'internalType': 'string',
             'name': 'a2',
             'type': 'string'}],
 'name': 'E',
 'type': 'event'}

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
    ├── exceptions.py
    ├── rlp.py
    ├── transaction.py
    └── validation.py
```

## Local Development

You can setup local version with

```bash
# Create new environment (you can use other name or reuse existing one)
python -m venv .env
. .env/bin/activate
# Editable install
pip install -e .[test]
# Install git hooks
pre-commit install
```

Or with help of `Makefile`:

```bash
# install dependencies
make install
# test code
make test
```

All project tests are based on `pytest`. You can use `tox` (configuration resides in `pyproject.toml`) to test against multiple `python` versions (it will also happen in CI, when you submit a PR).

You can run `pre-commit` hooks without commiting with

```bash
pre-commit run --all-files
```

We enforce strict coding style: `black` is a part of `pre-commit` setup, also it
includes `flake8` for additional validation.


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


## Upgrading to version 2.0.0

In version `2.0.0` a few backwards incompatible changes were introduced.

- Transaction methods `get_delgator`, `get_intrinsic_gas`, `get_signature`, `set_signature`, `get_origin` are deprecated in favour of properties. `Transaction.get_body` is replaced with `Transaction.body` property and `Transaction.copy_body()` method. `Transaction.is_delegated` is now a property instead of regular method.
- Certificate `__init__` method performs basic validation, so some invalid signatures will be rejected during instantiation and not in `verify` method. Module-level functions `encode` and `verify` are deprecated in favour of `Certificate` methods.
- `Bloom` filter has `__contains__` now (so you can use `element in bloom_filter`).
- ABI module has changed significantly. Function and Event can now be instantiated from solidity code with `from_solidity` method. New methods were introduced for encoding and decoding. `decode` results are now custom `namedtuple`'s instead of strange dictionary format, see docs for reference. `Event.get_signature` and `Function.get_selector` are deprecated in favour of `Event.signature` and `Function.selector` properties.
- RLP module functions `pack` and `unpack` are now deprecated, use `BaseWrapper` or `ScalarKind` `serialize` and `deserialize` methods instead.
- Functions with odd names `derive_publicKey` and `generate_privateKey` are deprecated in favour of `derive_public_key` and `generate_private_key`.
- `mnemonic.validate` is deprecated, use `mnemonic.is_valid` instead.
- `keystore.well_formed` is deprecated, use `keystore.validate` and `keystore.is_valid` instead.
- `HDNode` uses properties instead of methods for simple attributes: `private_key`, `public_key`, `chain_code`, `address`, `fingerprint`.
