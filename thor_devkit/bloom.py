"""Bloom filter implementation.

Bloom filter is a probabilistic data structure that is used to check
whether the element definitely is not in set or may be in the set.

Instead of a traditional hash-based set, that takes up too much memory,
this structure permits less memory with a tolerable false positive rate.

Used variables:

:``m``: Total bits of the filter.

:``k``: How many different hash functions to use.

:``n``: Number of elements to be added to the filter.

This implementation uses 2048 bits / 256 bytes of storage.
You can override it in a subclass.
"""
import math
import sys
from typing import Callable, Optional

from thor_devkit.cry import blake2b256

if sys.version_info < (3, 8):
    from typing_extensions import Literal
else:
    from typing import Literal

__all__ = ["Bloom"]


class Bloom:
    """Bloom filter.

    .. autoclasssumm:: Bloom
    """

    MAX_K: int = 16
    """Maximal amount of hash functions to use."""

    BITS_LENGTH: int = 2048
    """Filter size in bits."""

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

    def __init__(self, k: int, bits: Optional[bytes] = None):
        """Construct a bloom filter.

        Parameters
        ----------
        k : int
            The number of different hash functions to use.
        bits : Optional[bytes], optional
            Bits of previous bloom filter to inherit.
            Leave it :class:`None` to create an empty bloom filter.
        """
        self.k: int = k
        if bits is None:
            self.bits: bytes = bytes(self.BITS_LENGTH // 8)
        else:
            self.bits = bits

    def _distribute(self, element: bytes, tester: Callable[[int, int], bool]) -> bool:
        """Distribute the element into the bloom filter.

        Parameters
        ----------
        element : bytes
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

    def add(self, element: bytes) -> Literal[True]:
        """Add an element to the bloom filter.

        Parameters
        ----------
        element : bytes
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

    def test(self, element: bytes) -> bool:
        """Test if element is inside the bloom filter.

        Parameters
        ----------
        element : bytes
            The element in bytes.

        Returns
        -------
        bool
            ``True`` if inside, ``False`` if not inside.

        Warning
        -------
        If ``False`` is returned, then element is **sure** not in filter.

        If ``True`` is returned, then element **may be** in filter, there is no way
        to determine it surely.
        """

        def t(index: int, bit: int) -> bool:
            return (self.bits[index] & bit) == bit

        return self._distribute(element, t)

    def __contains__(self, element: bytes) -> bool:
        """Test if element is inside the bloom filter.

        Parameters
        ----------
        element : bytes
            The element in bytes.

        Returns
        -------
        bool
            ``True`` if inside, ``False`` if not inside.

        Warning
        -------
        If ``False`` is returned, then element is **sure** not in filter.

        If ``True`` is returned, then element **may be** in filter, there is no way
        to determine it surely.
        """
        return self.test(element)
