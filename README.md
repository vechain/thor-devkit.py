# VeChain Thor Devkit in Python 3

Python 3 Library to assist development on VeChain. Python 3.6+

# Install
```bash
pip3 install thor-devkit
```

# Get Started
```python
import thor-devkit
```

# Involve in Development

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

seed (used to derive bip32 keys): 64 bytes.
```