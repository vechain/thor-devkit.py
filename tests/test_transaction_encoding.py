import pytest
import requests
from thor_devkit import transaction, cry
from thor_devkit.block import Block
from thor_devkit.gas import Gas


@pytest.fixture
def http_client():
    session = requests.Session()
    session.base_url = 'https://testnet.vechain.org'
    def request_with_base_url(method, url, *args, **kwargs):
        if not url.startswith('http'):
            url = f"{session.base_url}{url}"
        return requests.request(method, url, *args, **kwargs)
    session.request = request_with_base_url
    return session

@pytest.fixture
def gas_client(http_client):
    return Gas(http_client)

@pytest.fixture
def block_client(http_client):
    return Block(http_client)


def test_legacy_vet_transfer(gas_client, block_client):
    vet_tx_legacy = {
        "chainTag": 246,
        "blockRef": "0x0151e082d4864082",
        "expiration": 32,
        "clauses": [
            {
                "to": '0x435933c8064b4ae76be665428e0307ef2ccfbd68',  # solo acc 2
                "value": 1,
                "data": '0x'
            },
        ],
        "gasPriceCoef": 128,
        "gas": 21000,
        "dependsOn": None,
        "nonce": 1
    }
    tx = transaction.Transaction(vet_tx_legacy, gas_module=gas_client, block_module=block_client)
    private_key = bytes.fromhex('99f0500549792796c14fed62011a51081dc5b5e68fe8bd8a13b86be829c4fd36') # solo acc 1
    tx_hash = tx.get_signing_hash()
    signature = cry.secp256k1.sign(tx_hash, private_key)
    tx.set_signature(signature)
    encoded_bytes = tx.encode()
    encoded_hex_str = encoded_bytes.hex()
    # this hex has been manually verified
    assert encoded_hex_str == "f87081f6880151e082d486408220d8d794435933c8064b4ae76be665428e0307ef2ccfbd68018081808252088001c0b8414a3fc9a43e7e614455273b9af19d6235600a56229036a8aaf8a5673fe65b67406c71f62b72a7c00f32fab830bb95822375666dad9296e6dceeedc01e1382295900"

def test_dynamic_fee_vet_transfer(gas_client, block_client):
    vet_tx_dynamic = {
        "type": 81,
        "chainTag": 246,
        "blockRef": "0x0151e082d4864082",
        "expiration": 32,
        "clauses": [
            {
                "to": '0x435933c8064b4ae76be665428e0307ef2ccfbd68',  # solo acc 2
                "value": 1,
                "data": '0x'
            },
        ],
        "maxPriorityFeePerGas": 1000,
        "maxFeePerGas": 100000,
        "gas": 21000,
        "dependsOn": None,
        "nonce": 1
    }
    tx = transaction.Transaction(vet_tx_dynamic, gas_module=gas_client, block_module=block_client)
    private_key = bytes.fromhex('99f0500549792796c14fed62011a51081dc5b5e68fe8bd8a13b86be829c4fd36')  # solo acc 1
    tx_hash = tx.get_signing_hash()
    signature = cry.secp256k1.sign(tx_hash, private_key)
    tx.set_signature(signature)
    encoded_bytes = tx.encode()
    encoded_hex_string = encoded_bytes.hex()
    assert encoded_hex_string == "51f87581f6880151e082d486408220d8d794435933c8064b4ae76be665428e0307ef2ccfbd6801808203e8830186a08252088001c0b84166ff82069aeb228a517e443d87ff2e644846850317b78970a91e79235159a7ad2783443b56dcf8c5438a61196a393fec76e070e50253eeccf2b552acf95a5e8900"
