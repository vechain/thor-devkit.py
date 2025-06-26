import pytest
import requests
from thor_devkit.block import Block, CompressedBlockDetail

@pytest.fixture
def http_client():
    session = requests.Session()
    session.base_url = 'https://galactica.live.dev.node.vechain.org' 
    return session

@pytest.fixture
def block_client(http_client):
    return Block(http_client)

def test_get_block_compressed(block_client):
    best_block = block_client.get_block_compressed('best')
    assert best_block is not None
    assert isinstance(best_block, CompressedBlockDetail)
    assert best_block.number >= 0
    assert best_block.id is not None
    assert best_block.timestamp > 0

    block_by_number = block_client.get_block_compressed(best_block.number)
    assert block_by_number is not None
    assert block_by_number.number == best_block.number
    assert block_by_number.id == best_block.id

    block_by_id = block_client.get_block_compressed(best_block.id)
    assert block_by_id is not None
    assert block_by_id.number == best_block.number
    assert block_by_id.id == best_block.id

def test_get_best_block_compressed(block_client):
    best_block = block_client.get_best_block_compressed()
    assert best_block is not None
    assert isinstance(best_block, CompressedBlockDetail)
    assert best_block.isTrunk is True 
def test_get_best_block_base_fee_per_gas(block_client):
    base_fee = block_client.get_best_block_base_fee_per_gas()
    if base_fee is not None:
        assert isinstance(base_fee, str)
        int(base_fee, 16)

def test_invalid_revision(block_client):
    with pytest.raises(Exception) as exc_info:
        block_client.get_block_compressed(-1) 
    assert 'Invalid revision' in str(exc_info.value)

    with pytest.raises(Exception) as exc_info:
        block_client.get_block_compressed('invalid_hex')
    assert 'Invalid revision' in str(exc_info.value)

def test_block_compressed_fields(block_client):
    best_block = block_client.get_best_block_compressed()
    assert best_block is not None
    
    assert isinstance(best_block.id, str)
    assert isinstance(best_block.number, int)
    assert isinstance(best_block.size, int)
    assert isinstance(best_block.parentID, str)
    assert isinstance(best_block.timestamp, int)
    assert isinstance(best_block.gasLimit, int)
    assert isinstance(best_block.beneficiary, str)
    assert isinstance(best_block.gasUsed, int)
    assert isinstance(best_block.totalScore, int)
    assert isinstance(best_block.txsRoot, str)
    assert isinstance(best_block.stateRoot, str)
    assert isinstance(best_block.receiptsRoot, str)
    assert isinstance(best_block.signer, str)
    assert isinstance(best_block.isTrunk, bool)