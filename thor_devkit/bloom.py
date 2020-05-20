'''
Bloom Filter.

A data structure tells us either the element definitely is not in,
or may be in the set.

Instead of a traditional hash-based set takes up too much memory,
this structure permits less memory with a tolerable false positive rate.

m = total bits of the filter.
k = how many different hash functions to use.
n = number of elements to be added to the filter.

2048 bits / 256 bytes
'''
import math
from typing import Callable
from .cry import blake2b256


class Bloom:
    MAX_K = 16
    BITS_LENGTH = 2048

    @classmethod
    def estimate_k(cls, count: int) -> int:
        '''
        Estimate the k based on the number of elements
        to be inserted into bloom filter.

        Parameters
        ----------
        count : int
            The number of elements to be inserted.

        Returns
        -------
        int
            The estimated k.
        '''
        k = round(cls.BITS_LENGTH / count * math.log(2))
        return max(min(k, cls.MAX_K), 1)

    def __init__(self, k: int, bits: bytes = None):
        '''
        Construct a bloom filter.
        k is the number of different hash functions.


        Parameters
        ----------
        k : int
            The number of different hash functions to use.
        bits : bytes, optional
            previous bloom filter to inherit, by default None.
            Leave it None to create an empty bloom filter.
        '''
        self.k = k
        if bits is None:
            self.bits = bytes(self.BITS_LENGTH//8)
        else:
            self.bits = bits

    def _distribute(self, element: bytes, tester: Callable[[int, int], bool]) -> bool:
        '''
        Distribute the element into the bloom filter.

        Parameters
        ----------
        element : bytes
            the element to be fit into the bloom filter.
        tester : Callable[[int, int], bool]
            a function to test the bit, return False to stop the operation.

        Returns
        -------
        bool
            True/False if element is inside during testing,
            or True when adding element.
        '''
        h, h_length = blake2b256([element])
        for x in range(0, self.k):
            d = (h[x * 2 + 1] + (h[x * 2] << 8)) % self.BITS_LENGTH
            bit = 1 << (d % 8)
            if not tester(int(d / 8), bit):
                return False
        return True

    def add(self, element: bytes) -> bool:
        '''
        Add an element to the bloom filter.

        Parameters
        ----------
        element : bytes
            The element in bytes.

        Returns
        -------
        bool
            True
        '''
        def t(index: int, bit: int):
            temp = list(self.bits)
            temp[index] = temp[index] | bit
            self.bits = bytes(temp)
            return True

        return self._distribute(element, t)

    def test(self, element: bytes) -> bool:
        '''
        Test if element is inside the bloom filter.

        Parameters
        ----------
        element : bytes
            The element in bytes.

        Returns
        -------
        bool
            True if inside, False if not inside.
        '''
        def t(index: int, bit: int):
            return (self.bits[index] & bit) == bit

        return self._distribute(element, t)
