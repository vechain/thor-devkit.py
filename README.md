# VeChain Thor Devkit in Python 3

Python 3 Library to assist development on VeChain. Python 3.6+

# Install
```bash
pip3 install thor-devkit
```

# Get Started
```python
import thor_devkit
```

# Involve in Development

## Caveat

Bip32 depends on the `ripemd160` hash library. Of which you should make sure it is installed on your system.

```bash
openssl list-message-digest-algorithms
```

and on Python3 :

```python

> python3

> import hashlib

> print hashlib.algorithms_available

```

## Project Layout
```
```

## Testing
```bash
python3 -m pytest
```

## Data Structure
```
private key: 32 bytes.

address: 20 bytes = 40 in hex string
keccak256: 256 bits = 32 bytes = 64 in hex string

message hash: 32 bytes.
signature: 65 bytes. (last bit as recovery parameter)

seed (used to derive bip32 master key): 64 bytes.
```