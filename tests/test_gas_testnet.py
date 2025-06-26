import pytest
import requests
from thor_devkit.gas import Gas

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

def test_get_max_priority_fee_per_gas_testnet(gas_client):
    result = gas_client.get_max_priority_fee_per_gas()
    assert isinstance(result, str)
    assert result.startswith('0x')
    int(result, 16) 