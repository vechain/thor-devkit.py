import copy
import pytest
from thor_devkit import certificate
from thor_devkit import cry

PRIV_KEY = bytes.fromhex(
    '7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a')
SIGNER = '0x' + \
    cry.public_key_to_address(cry.secp256k1.derive_publicKey(PRIV_KEY)).hex()

cert_dict = {
    'purpose': 'identification',
    'payload': {
        'type': 'text',
        'content': 'fyi'
    },
    'domain': 'localhost',
    'timestamp': 1545035330,
    'signer': SIGNER
}
cert = certificate.Certificate(**cert_dict)

cert2_dict = {
    'domain': 'localhost',
    'timestamp': 1545035330,
    'purpose': 'identification',
    'signer': SIGNER,
    'payload': {
        'content': 'fyi',
        'type': 'text'
    }
}
cert2 = certificate.Certificate(**cert2_dict)


def test_encode():
    assert certificate.encode(cert) == certificate.encode(cert2)

    temp = copy.deepcopy(cert_dict)
    temp['signer'] = temp['signer'].upper()
    temp_cert = certificate.Certificate(**temp)
    assert certificate.encode(cert) == certificate.encode(temp_cert)

    sig_bytes = cry.secp256k1.sign(
        cry.blake2b256([
            certificate.encode(cert).encode('utf-8')
        ])[0],
        PRIV_KEY
    )

    sig = '0x' + sig_bytes.hex()

    temp2 = copy.deepcopy(cert_dict)
    temp2['signature'] = sig
    temp2_cert = certificate.Certificate(**temp2)

    temp3 = copy.deepcopy(cert_dict)
    temp3['signature'] = sig.upper()
    temp3_cert = certificate.Certificate(**temp3)

    assert certificate.encode(temp2_cert) == certificate.encode(temp3_cert)


def test_verify():
    to_be_signed, _ = cry.blake2b256([
        certificate.encode(cert).encode('utf-8')
    ])

    sig_bytes = cry.secp256k1.sign(
        to_be_signed,
        PRIV_KEY
    )

    sig = '0x' + sig_bytes.hex()

    # Signature doesn't match.
    with pytest.raises(Exception, match='signature does not match with the signer.'):
        temp = copy.copy(cert_dict)
        temp['signature'] = sig
        temp['signer'] = '0x'
        certificate.verify(certificate.Certificate(**temp))

    # Everything is fine.
    temp2 = copy.copy(cert_dict)
    temp2['signature'] = sig
    certificate.verify(certificate.Certificate(**temp2))

    # Everything is fine.
    temp3 = copy.copy(cert_dict)
    temp3['signature'] = sig.upper()
    certificate.verify(certificate.Certificate(**temp3))
