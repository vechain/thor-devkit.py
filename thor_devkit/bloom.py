"""
Bloom Filter.

A data structure tells us either the element definitely is not in,
or may be in the set.

Instead of a traditional hash-based set takes up too much memory,
this structure permits less memory with a tolerable false positive rate.

m = total bits of the filter.
k = how many different hash functions to use.
n = number of elements to be added to the filter.

2048 bits / 256 bytes
"""
import math
import sys
from typing import Callable, Optional

from .cry import blake2b256
from .utils import _AnyBytes

if sys.version_info < (3, 8):
    from typing_extensions import Literal
else:
    from typing import Literal


class Bloom:
    MAX_K = 16
    BITS_LENGTH = 2048

    @classmethod
    def estimate_k(cls, count: int) -> int:
        """Estimate the k based on expected elements count.

        Parameters
        ----------
        count : int
            The number of elements to be inserted.

        Returns
        -------
        int
            The estimated k.
        """
        k = round(cls.BITS_LENGTH / count * math.log(2))
        return max(min(k, cls.MAX_K), 1)

    def __init__(self, k: int, bits: Optional[_AnyBytes] = None):
        """Construct a bloom filter.

        Parameters
        ----------
        k : int
            The number of different hash functions to use.
        bits : Optional[bytes or bytearray], optional
            Bits of previous bloom filter to inherit.
            Leave it ``None`` to create an empty bloom filter.
        """
        self.k = k
        if bits is None:
            self.bits = bytes(self.BITS_LENGTH // 8)
        else:
            self.bits = bits

    def _distribute(
        self, element: _AnyBytes, tester: Callable[[int, int], bool]
    ) -> bool:
        """Distribute the element into the bloom filter.

        Parameters
        ----------
        element : bytes or bytearray
            the element to be fit into the bloom filter.
        tester : Callable[[int, int], bool]
            a function to test the bit, return False to stop the operation.

        Returns
        -------
        bool
            ``True``/``False`` if element is inside during testing,
            or ``True`` when adding element.
        """
        h, _ = blake2b256([element])
        for x in range(self.k):
            d = (h[x * 2 + 1] + (h[x * 2] << 8)) % self.BITS_LENGTH
            bit = 1 << (d % 8)
            if not tester(int(d / 8), bit):
                return False
        return True

    def add(self, element: _AnyBytes) -> Literal[True]:
        """Add an element to the bloom filter.

        Parameters
        ----------
        element : bytes or bytearray
            The element in bytes.

        Returns
        -------
        Literal[True]
            Always ``True``
        """

        def t(index: int, bit: int) -> Literal[True]:
            temp = list(self.bits)
            temp[index] = temp[index] | bit
            self.bits = bytes(temp)
            return True

        assert self._distribute(element, t)
        return True

    def test(self, element: _AnyBytes) -> bool:
        """Test if element is inside the bloom filter.

        Parameters
        ----------
        element : bytes or bytearray
            The element in bytes.

        Returns
        -------
        bool
            ``True`` if inside, ``False`` if not inside.
        """

        def t(index: int, bit: int) -> bool:
            return (self.bits[index] & bit) == bit

        return self._distribute(element, t)

    def __contains__(self, element: _AnyBytes) -> bool:
        return self.test(element)
