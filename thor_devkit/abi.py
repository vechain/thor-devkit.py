'''
ABI Module.

ABI structure the "Functions" and "Events".

ABI also encode/decode params for functions.

See:
https://github.com/ethereum/wiki/wiki/Ethereum-Contract-ABI

"Function Selector":
sha3("funcName(uint256,address)") -> cut out first 4 bytes.

"Argument Encoding":

Basic:
uint<M> M=8,16,...256
int<M> M=8,16,...256
address
bool
fixed<M>x<N> fixed256x18
bytes<M> bytes32
function 20bytes address + 4 bytes signature.

Fixed length:
<type>[M] Fix sized array. int[10], uint256[33], 

Dynamic length:
bytes
string
<type>[]
'''

# voluptuous is a better library in validating dict.

from typing import List, Optional
from enum import Enum
import eth_utils
import eth_abi

MUTABILITY = ['pure', 'view', 'constant', 'payable', 'nonpayable']

def _is_legal_mutability(input: str):
    if input in MUTABILITY:
        return True
    else:
        return False
