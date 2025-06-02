import pytest
import requests
from unittest.mock import Mock, patch
from thor_devkit.gas import Gas

def test_get_max_priority_fee_per_gas_success():
    mock_response = {
        'maxPriorityFeePerGas': '0x1f0'
    }
    
    mock_session = Mock(spec=requests.Session)
    mock_response_obj = Mock()
    mock_response_obj.json.return_value = mock_response
    mock_session.get.return_value = mock_response_obj
    
    gas = Gas(mock_session)
    
    result = gas.get_max_priority_fee_per_gas()
    
    assert result == '0x1f0'
    mock_session.get.assert_called_once_with('/fees/priority')

def test_get_max_priority_fee_per_gas_invalid_response():
    mock_session = Mock(spec=requests.Session)
    mock_session.get.return_value = None
    
    gas = Gas(mock_session)
    
    with pytest.raises(Exception) as exc_info:
        gas.get_max_priority_fee_per_gas()
    
    assert 'Invalid response format' in str(exc_info.value)

def test_get_max_priority_fee_per_gas_missing_field():
    mock_response = {}
    
    mock_session = Mock(spec=requests.Session)
    mock_response_obj = Mock()
    mock_response_obj.json.return_value = mock_response
    mock_session.get.return_value = mock_response_obj
    
    gas = Gas(mock_session)
    
    with pytest.raises(Exception) as exc_info:
        gas.get_max_priority_fee_per_gas()
    
    assert 'Missing or invalid maxPriorityFeePerGas' in str(exc_info.value)

def test_get_max_priority_fee_per_gas_invalid_field_type():
    mock_response = {
        'maxPriorityFeePerGas': 123 
    }
    
    mock_session = Mock(spec=requests.Session)
    mock_response_obj = Mock()
    mock_response_obj.json.return_value = mock_response
    mock_session.get.return_value = mock_response_obj
    
    gas = Gas(mock_session)
    
    with pytest.raises(Exception) as exc_info:
        gas.get_max_priority_fee_per_gas()
    
    assert 'Missing or invalid maxPriorityFeePerGas' in str(exc_info.value)

def test_get_max_priority_fee_per_gas_empty_field():
    mock_response = {
        'maxPriorityFeePerGas': ''
    }
    
    mock_session = Mock(spec=requests.Session)
    mock_response_obj = Mock()
    mock_response_obj.json.return_value = mock_response
    mock_session.get.return_value = mock_response_obj
    
    gas = Gas(mock_session)
    
    with pytest.raises(Exception) as exc_info:
        gas.get_max_priority_fee_per_gas()
    
    assert 'Missing or invalid maxPriorityFeePerGas' in str(exc_info.value) 