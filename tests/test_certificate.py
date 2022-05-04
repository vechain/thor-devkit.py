from datetime import datetime

import pytest

from thor_devkit.certificate import Certificate, CertificateT
from thor_devkit.cry import blake2b256, public_key_to_address, secp256k1
from thor_devkit.exceptions import BadSignature


@pytest.fixture()
def private_key():
    return bytes.fromhex(
        "7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a"
    )


@pytest.fixture()
def signer(private_key):
    return "0x" + public_key_to_address(secp256k1.derive_publicKey(private_key)).hex()


@pytest.fixture()
def cert_1(signer):
    data: CertificateT = {
        "purpose": "identification",
        "payload": {"type": "text", "content": "fyi"},
        "domain": "localhost",
        "timestamp": 1545035330,
        "signer": signer,
    }
    return Certificate(**data)


@pytest.fixture()
def cert_2(signer):
    data: CertificateT = {
        "domain": "localhost",
        "timestamp": datetime.fromtimestamp(1545035330),
        "purpose": "identification",
        "signer": signer,
        "payload": {"content": "fyi", "type": "text"},
    }
    return Certificate(**data)


def test_encode_basic(cert_1, cert_2):
    assert cert_1.encode() == cert_1.encode()
    assert cert_1.encode() == cert_2.encode()


def test_signer_is_case_insensitive(cert_1):
    data = cert_1.to_dict()
    data["signer"] = data["signer"].upper()
    assert cert_1.encode() == Certificate(**data).encode()


def test_signature_is_case_insensitive(cert_1, private_key):
    sig_bytes = secp256k1.sign(blake2b256([cert_1.encode().encode()])[0], private_key)
    sig = "0x" + sig_bytes.hex()
    sig_lower_cert = Certificate(**cert_1.to_dict(), signature=sig)
    sig_upper_cert = Certificate(**cert_1.to_dict(), signature=sig.upper())
    assert sig_lower_cert.encode() == sig_upper_cert.encode()


def test_verify(cert_1, private_key):
    to_be_signed, _ = blake2b256([cert_1.encode().encode()])

    sig_bytes = secp256k1.sign(to_be_signed, private_key)
    sig = "0x" + sig_bytes.hex()

    # Everything is fine.
    Certificate(**cert_1.to_dict(), signature=sig).verify()
    Certificate(**cert_1.to_dict(), signature=sig.upper()).verify()

    # Signature doesn't match.
    temp = cert_1.to_dict()
    temp["signer"] = "0x"
    with pytest.raises(BadSignature):
        Certificate(**temp, signature=sig).verify()
