'''
Transaction class defines VeChain's multi-clause transaction.
'''
from typing import Union, List, Optional
from .rlp import NumericKind

# New kind, used for VeChain's "reserved features" kind.
FeaturesKind = NumericKind(4)


class Clause():
    '''
    Clause type.
    Consists of the "destination", the "vet value" to pass to, and the "data" to pass to.
    '''

    def __init__(self, to: Union[str, None], value: Union[str, int], data: str):
        '''
        Create a clause.

        Parameters
        ----------
        to : Union[str, None]
            Destination contract address, or set to None to create contract.
        value : Union[str, int]
            VET to pass to the call.
        data : str
            data for contract method invocation or deployment.
        '''
        self.to = to
        self.value = value
        self.data = data
    
    def __dict__(self) -> dict:
        return {
            "to": self.to,
            "value": self.value,
            "data": self.data
        }


class Reserved():
    ''' Reserved type.
    Mark the transaction body if the new supplement features are used.
    '''
    def __init__(
            self,
            features: int = None,
            unused: List[int] = None):

        self.features = features
        self.unused = unused
    
    def __dict__(self) -> dict:
        return {
            "features": self.features,
            "unused": self.unused
        }


class Body():
    ''' Body type.
    Consists of the structure of the body of a transaction.
    '''
    def __init__(
            self,
            chain_tag: int,
            block_ref: str,
            expiration: int,
            clauses: List[Clause],
            gas_price_coef: int,
            gas: Union[str, int],
            depends_on: Union[str, None],
            nonce: Union[str, int],
            reserved: Optional[Reserved] = None):

        self.chain_tag = chain_tag,
        self.block_ref = block_ref
        self.expiration = expiration
        self.clauses = clauses
        self.gas_price_coef = gas_price_coef
        self.gas = gas
        self.depends_on = depends_on
        self.nonce = nonce
        self.reserved = reserved
    
    def __dict__(self) -> dict:
        d = {
            "chainTag": self.chain_tag,
            "blockRef": self.block_ref,
            "expiration": self.expiration,
            "clauses": self.clauses,
            "gasPriceCoef": self.gas_price_coef,
            "gas": self.gas,
            "dependsOn": self.depends_on,
            "nonce": self.nonce
        }

        if self.reserved:
            r = {}
            if self.reserved.features:
                r["features"] = self.reserved.features
            
            if self.reserved.unused:
                r["unused"] = self.reserved.unused
            
            d['r'] = r
        
        return d


def data_gas(data: str) -> int:
    '''
    Calculate the gas the data will consume.

    Parameters
    ----------
    data : str
        '0x...' style hex string.
    '''
    Z_GAS = 4
    NZ_GAS = 68

    sum_up = 0
    for x in range(2, len(data), 2):
        if data[x] == '0' and data[x+1] == '0':
            sum_up += Z_GAS
        else:
            sum_up += NZ_GAS

    return sum_up


def instrinsic_gas(clauses: List[Clause]) -> int:
    '''
    Calculate roughly the gas from a list of clauses.

    Parameters
    ----------
    clauses : List[Clause]
        A list of clauses.

    Returns
    -------
    int
        The sum of gas.
    '''
    TX_GAS = 5000
    CLAUSE_GAS = 16000
    CLAUSE_CONTRACT_CREATION = 48000

    if len(clauses) == 0:
        return TX_GAS + CLAUSE_GAS

    sum_total = 0
    sum_total += TX_GAS

    for clause in clauses:
        clause_sum = 0
        if clause.to == None:  # contract create.
            clause_sum += CLAUSE_GAS
        else:
            clause_sum += CLAUSE_CONTRACT_CREATION
        clause_sum += data_gas(clause.data)

        sum_total += clause_sum

    return sum_total


class Transaction():
    # The reserved feature of delegated (vip-191) is 1.
    DELEGATED_MASK = 1

    def __init__(self, body: Body):
        ''' Contruct a transaction from a given body.'''
        self.body = body
        self.signature = None
    
    def _encode_reserved(self):
        reserved = self.body.reserved or Reserved(None, None)
        f = reserved.features or 0
        l = reserved.unused or []
        m_list = [FeaturesKind.serialize(f)] + l

        # While some elements in the m_list is b'' or '',
        # Then just right strip those '' from the list.
        length_list = [len(x) for x in m_list]

        right_most_none_empty = None
        for i in range( len(length_list) - 1, -1, -1):
            if length_list[i] != 0:
                right_most_none_empty = i
                break
        
        if right_most_none_empty is None: # not found the right most none-empty string item
            return []
        
        return_list = []
        for y in range(0, right_most_none_empty + 1):
            return_list.append(m_list[y])
        
        return return_list


    def signing_hash(self, delegate_for: str = None) -> bytes:
        # TODO
        reserved = self._encode_reserved()

    def get_signature(self) -> Union[None, bytes]:
        ''' Get the signature of current transaction.'''
        return self.signature

    def get_intrinsic_gas(self) -> int:
        ''' Get the rough gas this tx will consume'''
        return instrinsic_gas(self.body.clauses)

    def get_origin(self) -> Union[None,str]:
        ''' Get the "origin" of this tx'''
        if not self._signature_valid():
            return None
        
        try:
            # TODO
            pass
        except:
            pass

    def is_delegated(self):
        ''' Check if this transaction is delegated.'''
        if not self.body.reserved:
            return False
        
        if not self.body.reserved.features:
            return False
        
        return self.body.reserved.features & self.DELEGATED_MASK == self.DELEGATED_MASK

    def _signature_valid(self) -> bool:
        if self.is_delegated:
            expected_sig_len = 65 *2
        else:
            expected_sig_len = 65

        if not self.get_signature:
            return False
        else:
            return len(self.get_signature) == expected_sig_len

    def get_id(self) -> Union[None, str]:
        ''' Get the current transaction Id, None if something went wrong'''
        if not self._signature_valid():
            return None
        
        try:
            # TODO
            pass
        except:
            pass