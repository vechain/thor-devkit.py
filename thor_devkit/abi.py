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
from voluptuous import Schema, Any, Optional
from typing import List
from typing import Union
import eth_utils
import eth_abi
from .cry import keccak256


MUTABILITY = Schema(Any('pure', 'view', 'constant', 'payable', 'nonpayable'))


FUNC_PARAMETER = Schema({
        "name": str,
        "type": str,
        Optional("components"): list, # if the "type" field is "tuple" or "type[]"
        Optional("internalType"): str
    },
    required=True
)


FUNCTION = Schema({
        "type": "function",
        "name": str,
        Optional("constant"): bool,
        Optional("payable"): bool,
        "stateMutability": MUTABILITY,
        "inputs": [FUNC_PARAMETER],
        "outputs": [FUNC_PARAMETER]
    },
    required=True
)


EVENT_PARAMETER = Schema({
        "name": str,
        "type": str,
        "indexed": bool
    },
    required=True
)


EVENT = Schema({
    "type": "event",
    "name": str,
    Optional("anonymous"): bool,
    "inputs": [EVENT_PARAMETER]
})


def is_dynamic_type(t: str):
    ''' Check if the input type is dynamic '''
    if t == 'bytes' or t == 'string' or t.endswith('[]'):
        return True
    else:
        return False


def dynamic_type_to_topic(t_type:str, value):
    if t_type == 'string':
        return keccak256([value.encode('utf-8')])[0]
    elif t_type == 'bytes':
        return keccak256([value])[0]
    else:
        raise ValueError('complex value type {} is not supported yet, open an issue on Github.'.format(t_type))


def calc_function_selector(abi_json: dict) -> bytes:
    ''' Calculate the function selector (4 bytes) from the abi json '''
    f = FUNCTION(abi_json)
    return eth_utils.function_abi_to_4byte_selector(f)


def calc_event_topic(abi_json: dict) -> bytes:
    ''' Calculate the event log topic (32 bytes) from the abi json'''
    e = EVENT(abi_json)
    return eth_utils.event_abi_to_log_topic(e)


class Coder():
    @staticmethod
    def encode_list(types: List[str], values) -> bytes:
        ''' Encode a sequence of values, into a single bytes '''
        return eth_abi.encode_abi(types, values)

    @staticmethod
    def decode_list(types: List[str], data: bytes) -> List:
        ''' Decode the data, back to a (,,,) tuple '''
        return list(eth_abi.decode_abi(types, data))
    
    @staticmethod
    def encode_single(t: str, value) -> bytes:
        ''' Encode value of type t into single bytes'''
        return Coder.encode_list([t], [value])

    @staticmethod
    def decode_single(t: str, data):
        ''' Decode data of type t back to a single object'''
        return Coder.decode_list([t], data)[0]


class Function():
    def __init__(self, f_definition: dict):
        '''Initialize a function by definition.

        Parameters
        ----------
        f_definition : dict
            See FUNCTION type in this document.
        '''
        self._definition = FUNCTION(f_definition) # Protect.
        self.selector = calc_function_selector(f_definition) # first 4 bytes.
    
    def encode(self, parameters: List, to_hex=False) -> Union[bytes, str]:
        '''Encode the paramters according to the function definition.

        Parameters
        ----------
        parameters : List
            A list of parameters waiting to be encoded.
        to_hex : bool, optional
            If the return should be '0x...' hex string, by default False

        Returns
        -------
        Union[bytes, str]
            Return bytes or '0x...' hex string if needed.
        '''
        my_types = [x['type'] for x in self._definition['inputs']]
        my_bytes = self.selector + Coder.encode_list(my_types, parameters)
        if to_hex:
            return '0x' + my_bytes.hex()
        else:
            return my_bytes
    
    def decode(self, output_data: bytes) -> dict:
        '''Decode function call output data back into human readable results.

        The result is in dual format. Contains both position and named index.
        eg. { '0': 'john', 'name': 'john' }
        '''
        my_types = [x['type'] for x in self._definition['outputs']]
        my_names = [x['name'] for x in self._definition['outputs']]

        result_list = Coder.decode_list(my_types, output_data)

        r = {}
        for idx, name in enumerate(my_names):
            r[str(idx)] = result_list[idx]
            if name:
                r[name] = result_list[idx]
        
        return r


class Event():
    def __init__(self, e_definition: dict):
        '''Initialize an Event with definition.

        Parameters
        ----------
        e_definition : dict
            A dict with style of EVENT.
        '''
        self._definition = EVENT(e_definition)
        self.signature = calc_event_topic(self._definition)

    def encode(self, params: Union[dict, List]) -> List:
        '''Assemble indexed keys into topics.

        Usage
        -----

        Commonly used to filter out logs of concerned topics,
        eg. To filter out VIP180 transfer logs of a certain wallet, certain amount.

        Parameters
        ----------
        params : Union[dict, List]
            A dict/list of indexed param of the given event,
            fill in None to occupy the position,
            if you aren't sure about the value.

            eg. For event:
            
            EventName(address from indexed, address to indexed, uint256 value)

            the params can be: 
            ['0xa32f..ff', '0x1f...ac']
            or:
            {'from': '0xa32f..ff', 'to': '0x1f...ac'}
            or:
            [None, '0x1f...ac']
            or:
            {'from': None, 'to': '0x1f...ac'}

        Returns
        -------
        List
            [description]

        Raises
        ------
        ValueError
            [description]
        '''
        topics = []

        # not anonymous? topic[0] = signature.
        if self._definition.get('anonymous', False) == False:
            topics.append(self.signature)

        indexed_params = [x for x in self._definition['inputs'] if x['indexed']]
        has_no_name_param = any([True for x in indexed_params if not x['name']])

        # Check #1
        if type(params) != list and has_no_name_param:
            raise ValueError('Event definition contains param without a name, use a list of params instead of dict.')

        # Check #2
        if type(params) == list and len(params) != len(indexed_params):
            raise ValueError('Indexed params needs {} length, {} is given.'.format(len(indexed_params), len(params)))

        # Check #3
        if type(params) == dict and len(params.keys()) != len(indexed_params):
            raise ValueError('Indexed params needs {} keys, {} is given.'.format(len(indexed_params), len(params.keys())))

        if type(params) == list:
            for param, definition in zip(params, indexed_params):
                if is_dynamic_type( definition['type'] ):
                    topics.append( dynamic_type_to_topic(definition['type'], param) )
                else:
                    topics.append( Coder.encode_single(definition['type'], param) )

        if type(params) == dict:
            for definition in indexed_params:
                value = params.get(definition['name'], None)
                if value is None:
                    topics.append(value)
                    continue

                if is_dynamic_type( definition['type'] ):
                    topics.append( dynamic_type_to_topic(definition['type'], value) )
                else:
                    topics.append( Coder.encode_single(definition['type'], value) )

        return topics


    def decode(self, data: bytes, topics: List[bytes]):
        ''' Decode "data" according to the "topic"s.

        One output can contain an array of logs[].
        One log contains mainly 3 entries:

        - For a non-indexed parameters event:

            "address": The emitting contract address.
            "topics": [
                "signature of event"
            ]
            "data": "0x..." (contains parameters value)

        - For an indexed parameters event:

            "address": The emitting contract address.
            "topics": [
                "signature of event",
                "indexed param 1",
                "indexed param 2",
                ...
                --> max 3 entries of indexed params.
            ]
            "data": "0x..." (remain un-indexed parameters value)

        If the event is "anonymous" then the signature is not inserted into the "topics" list,
        hence topics[0] is not the signature.
        '''
        if self._definition.get('anonymous', False) == False:
            # if not anonymous, topics[0] is the signature of event.
            # we cut it out, because we already have self.signature
            topics = topics[1:]
        
        _indexed_params_definitions = [x for x in self._definition['inputs'] if x['indexed']]
        _un_indexed_params_definitions = [x for x in self._definition['inputs'] if not x['indexed']]

        if len(_indexed_params_definitions) != len(topics):
            raise Exception('topics count invalid.')
            
        un_indexed_params = Coder.decode_list(
            [x['type'] for x in _un_indexed_params_definitions],
            data
        )

        r = {}
        for idx, each in enumerate(self._definition['inputs']):
            to_be_stored = None
            if each['indexed']:
                topic = topics.pop(0)
                if is_dynamic_type(each['type']):
                    to_be_stored = topic
                else:
                    to_be_stored = Coder.decode_single(each['type'], topic)
            else:
                to_be_stored = un_indexed_params.pop(0)

            r[str(idx)] = to_be_stored

            if each['name']:
                r[each['name']] = to_be_stored

        return r