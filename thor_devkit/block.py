import requests
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass
from urllib.parse import urljoin

@dataclass
class CompressedBlockDetail:
    id: str
    number: int
    size: int
    parentID: str
    timestamp: int
    gasLimit: int
    beneficiary: str
    gasUsed: int
    totalScore: int
    txsRoot: str
    stateRoot: str
    receiptsRoot: str
    signer: str
    isTrunk: bool
    baseFeePerGas: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CompressedBlockDetail':
        """
        Create a CompressedBlockDetail instance from a dictionary.
        Handles field name mapping and type conversion.

        Parameters
        ----------
        data : Dict[str, Any]
            The dictionary containing block data from the API

        Returns
        -------
        CompressedBlockDetail
            A new instance with the data from the dictionary
        """
        # Map API response fields to our dataclass fields
        mapped_data = {
            'id': data.get('id'),
            'number': int(data.get('number', 0)),
            'size': int(data.get('size', 0)),
            'parentID': data.get('parentID'),
            'timestamp': int(data.get('timestamp', 0)),
            'gasLimit': int(data.get('gasLimit', 0)),
            'beneficiary': data.get('beneficiary'),
            'gasUsed': int(data.get('gasUsed', 0)),
            'totalScore': int(data.get('totalScore', 0)),
            'txsRoot': data.get('txsRoot'),
            'stateRoot': data.get('stateRoot'),
            'receiptsRoot': data.get('receiptsRoot'),
            'signer': data.get('signer'),
            'isTrunk': bool(data.get('isTrunk', False)),
            'baseFeePerGas': data.get('baseFeePerGas')
        }
        return cls(**mapped_data)

class Block:
    """
    The `Block` class encapsulates functionality for interacting with blocks
    on the VeChainThor blockchain.
    """
    def __init__(self, http_client: requests.Session):
        """
        Initialize the Block module with an HTTP client.

        Parameters
        ----------
        http_client : requests.Session
            An HTTP client session for making requests to the VeChain network.
        """
        self.http_client = http_client

    def get_block_compressed(self, revision: Union[str, int]) -> Optional[CompressedBlockDetail]:
        """
        Retrieves details of a compressed specific block identified by its revision (block number or ID).

        Parameters
        ----------
        revision : Union[str, int]
            The block number or ID to query details for.

        Returns
        -------
        Optional[CompressedBlockDetail]
            The compressed block details, or None if not found.

        Raises
        ------
        Exception
            If the revision is invalid or if there's an error in the request.
        """
        # Check if the revision is a valid block number or ID
        if revision is not None and not self._is_valid_revision(revision):
            raise Exception(
                'Block.get_block_compressed()',
                'Invalid revision. The revision must be a string representing a block number or block id (also "best" is accepted which represents the best block & "finalized" for the finalized block).',
                {'revision': revision}
            )

        url = urljoin(self.http_client.base_url, f'/blocks/{revision}')
        response = self.http_client.get(url)
        if response is None:
            return None

        try:
            data = response.json()
            if data is None:
                return None
            return CompressedBlockDetail.from_dict(data)
        except Exception as e:
            raise Exception(
                'Block.get_block_compressed()',
                'Invalid response format from /blocks endpoint',
                {'error': str(e), 'data': data if 'data' in locals() else None}
            )

    def get_best_block_compressed(self) -> Optional[CompressedBlockDetail]:
        """
        Retrieves details of the latest block.

        Returns
        -------
        Optional[CompressedBlockDetail]
            The compressed block details of the latest block, or None if not found.
        """
        return self.get_block_compressed('best')

    def get_best_block_base_fee_per_gas(self) -> Optional[str]:
        """
        Retrieves the base fee per gas of the best block.

        Returns
        -------
        Optional[str]
            The base fee per gas of the best block, or None if not found.
        """
        best_block = self.get_best_block_compressed()
        print("best_block", best_block)
        if best_block is None:
            return None
        return best_block.baseFeePerGas

    def _is_valid_revision(self, revision: Union[str, int]) -> bool:
        """
        Validates if the revision is valid.
        A valid revision can be:
        - A positive integer
        - The string 'best'
        - The string 'finalized'
        - A valid block ID (hex string)

        Parameters
        ----------
        revision : Union[str, int]
            The revision to validate.

        Returns
        -------
        bool
            True if the revision is valid, False otherwise.
        """
        if isinstance(revision, int):
            return revision >= 0
        if isinstance(revision, str):
            if revision in ['best', 'finalized']:
                return True
            # Check if it's a valid hex string (block ID)
            try:
                int(revision, 16)
                return True
            except ValueError:
                return False
        return False 