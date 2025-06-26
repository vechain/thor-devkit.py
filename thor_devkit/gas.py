import requests
from typing import Dict, Any, Optional
from dataclasses import dataclass

class Gas:
    """
    The `Gas` class handles gas related operations and provides
    convenient methods for estimating the gas cost of a transaction.
    """
    def __init__(self, http_client: requests.Session):
        """
        Initialize the Gas module with an HTTP client.

        Parameters
        ----------
        http_client : requests.Session
            An HTTP client session for making requests to the VeChain network.
        """
        self.http_client = http_client

    def get_max_priority_fee_per_gas(self) -> str:
        """
        Returns the suggested priority fee per gas in wei.
        This is calculated based on the current base fee and network conditions.

        Returns
        -------
        str
            Suggested priority fee per gas in wei (hex string)

        Raises
        ------
        Exception
            If the response format is invalid or missing required data.
        """
        response = self.http_client.get('/fees/priority')
        
        # Check if response is None
        if response is None:
            raise Exception(
                'get_max_priority_fee_per_gas()',
                'Invalid response format from /fees/priority endpoint',
                {'response': None}
            )

        try:
            data = response.json()
        except Exception as e:
            raise Exception(
                'get_max_priority_fee_per_gas()',
                'Invalid response format from /fees/priority endpoint',
                {'response': str(e)}
            )

        # Validate response
        if not isinstance(data, dict):
            raise Exception(
                'get_max_priority_fee_per_gas()',
                'Invalid response format from /fees/priority endpoint',
                {'response': data}
            )

        if (
            'maxPriorityFeePerGas' not in data or
            data['maxPriorityFeePerGas'] is None or
            data['maxPriorityFeePerGas'] == '' or
            not isinstance(data['maxPriorityFeePerGas'], str)
        ):
            raise Exception(
                'get_max_priority_fee_per_gas()',
                'Missing or invalid maxPriorityFeePerGas in response',
                {'response': data}
            )

        return data['maxPriorityFeePerGas']
        