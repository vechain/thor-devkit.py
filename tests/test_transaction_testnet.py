import pytest
import requests
from thor_devkit import transaction
from thor_devkit.gas import Gas
from thor_devkit.block import Block

pytestmark = pytest.mark.asyncio

@pytest.fixture
def http_client():
    session = requests.Session()
    session.base_url = 'https://galactica.live.dev.node.vechain.org'
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

dynamic_fee_transaction_body = {
  "id": '0xf47542ebf813c723fa087b342db4c5f67866cc1b03b362c37a1b1766cac5c53a',
  "type": 81,
  "chainTag": 228,
  "blockRef": '0x0001c400b93e3f87',
  "expiration": 30,
  "clauses": [
    {
      "to": '0x17c5fab5980157d0f2c14e1056e8ad828b43bb52',
      "value": '0x0',
      "data": '0xaecb29bf00000000000000000000000000000000000000000000000000000000000000977b7b81982ec56e3763f3a525d3675aacae0184a2fbeca967b8f5a979d6480e8a1c40ecc470246fba5958922b2554f93d946680a434f161b8e6cb5d63dfc1cdf5'
    }
  ],
  "gas": 946888,
  "origin": '0xa7d07b0176e8ec925f59bc3e75a4044f56991d3a',
  "nonce": '0xb7643a8f91b25566',
  "size": 5150,
  "dependsOn": None,
  "meta": {
    "blockID": '0x0001c4016673373aac9a43f3730e32ef019ec22e055524f9417b2486ee958a57',
    "blockNumber": 115713,
    "blockTimestamp": 1748289731
  }
}

async def test_fill_default_body_options_testnet(gas_client, block_client):
    tx = transaction.Transaction(dynamic_fee_transaction_body, gas_module=gas_client, block_module=block_client)
    
    await tx.fill_default_body_options()
    body = tx.get_body()

    
    if 'maxPriorityFeePerGas' in body:
        assert body['maxPriorityFeePerGas'].startswith('0x')
        int(body['maxPriorityFeePerGas'], 16) 
        
    if 'maxFeePerGas' in body:
        assert body['maxFeePerGas'].startswith('0x')
        int(body['maxFeePerGas'], 16) 
        
        if 'maxPriorityFeePerGas' in body:
            max_fee = int(body['maxFeePerGas'], 16)
            priority_fee = int(body['maxPriorityFeePerGas'], 16)
            assert max_fee > priority_fee
  