# VeChain Thor Devkit in Python 3

Python 3 Library to assist development on VeChain. Python 3.6+

# Install
```bash
pip3 install thor-devkit
```

`Caveat: Bip32 depends on the ripemd160 hash library, which should be installed on your system.`

# Get Started
```python
import thor_devkit

```

# Tweak the Code

## Layout
```
.
├── LICENSE
├── README.md
├── requirements.txt
├── test.sh
├── tests/
└── thor_devkit/
    ├── cry/
    │   ├── __init__.py
    │   ├── address.py
    │   ├── blake2b.py
    │   ├── hdnode.py
    │   ├── keccak.py
    │   ├── keystore.py
    │   ├── mnemonic.py
    │   └── secp256k1.py
    ├── __init__.py
    ├── abi.py
    ├── bloom.py
    ├── certificate.py
    ├── rlp.py
    └── transaction.py
```

## Testing
```bash
./test.sh
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
