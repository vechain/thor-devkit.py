''' 
User signed certificate.

https://github.com/vechain/VIPs/blob/master/vips/VIP-192.md
'''
from typing import Optional
import json
import re
import copy
from .cry import blake2b256
from .cry import secp256k1
from .cry import address


class Certificate():
    def __init__(
        self,
        purpose: str,
        payload: dict,
        domain: str,
        timestamp: int,
        signer: str,
        signature: Optional[str] = None
    ):
        '''
        Certficate itself.

        Parameters
        ----------
        purpose : str
            A String.
        payload : dict
            Of style { "type": str, "content": str}
        domain : str
            A String
        timestamp : int
            Integer, Unix timestamp.
        signer : str
            0x... the signer address.
        signature : Optional[str], optional
            A secp256k1 signed bytes, but turned into a '0x' + bytes.hex() format, by default None
        '''
        if not payload.get('type'):
            raise ValueError('payload needs a string field "type"')
        if not payload.get('content'):
            raise ValueError('payload needs a string field "content"')

        self.obj = {
            'purpose': purpose,
            'payload': payload,
            'domain': domain,
            'timestamp': timestamp,
            'signer': signer
        }

        if signature:
            self.obj['signature'] = signature

    def to_dict(self):
        return self.obj


def safe_tolowercase(s: str):
    if type(s) == str:
        return s.lower()
    else:
        return s


def encode(cert: Certificate) -> str:
    '''
    Encode a certificate into json.

    Parameters
    ----------
    cert : Certificate
        The certificate to be encoded.

    Returns
    -------
    str
        The encoded string.
    '''
    temp = cert.to_dict()
    temp['signer'] = safe_tolowercase(temp['signer'])
    if temp.get('signature'):
        temp['signature'] = safe_tolowercase(temp['signature'])

    # separators=(',', ':') -> no whitespace compact string
    # sort_keys -> dict key is ordered.
    return json.dumps(temp, separators=(',', ':'), sort_keys=True)


SIGNATURE_PATTERN = re.compile('^0x[0-9a-f]+$', re.I)


def verify(cert: Certificate):
    temp = cert.to_dict()
    if not temp.get('signature'):
        raise ValueError('Cert needs a "signature" field.')

    sig = copy.copy(temp['signature'])
    if len(sig) % 2 != 0:
        raise ValueError('Cert "signature" field needs to be of even length.')

    if not SIGNATURE_PATTERN.match(sig):
        raise ValueError('Cert "signature" field can not pass the style check')

    # remove the signature, then encode.
    del temp['signature']
    the_encoded = encode(Certificate(**temp))
    signing_hash, _ = blake2b256([the_encoded.encode('utf-8')])
    pub_key = secp256k1.recover(signing_hash, bytes.fromhex(sig[2:]))

    if '0x' + address.public_key_to_address(pub_key).hex() != safe_tolowercase(temp['signer']):
        raise Exception('signature does not match with the signer.')
