import warnings
from typing import Callable, TypeVar

_C = TypeVar("_C", bound=Callable)


def deprecated_to_property(func: _C) -> _C:
    def inner(*args, **kwargs):
        warnings.warn(
            DeprecationWarning("This method is deprecated, use property instead")
        )
        return func(*args, **kwargs)

    return inner
