import warnings
from typing import Any, Callable, Type, TypeVar, cast

_C = TypeVar("_C", bound=Callable)
_T = TypeVar("_T", bound=Type)


def deprecated_to_property(func: _C) -> _C:  # pragma: no cover
    def inner(*args, **kwargs):
        warnings.warn(
            DeprecationWarning("This method is deprecated, use property instead")
        )
        return func(*args, **kwargs)

    return cast(_C, inner)


def class_renamed(cls: _T, old_name: str) -> _T:
    def __init__(self, *args: Any, **kwargs: Any) -> None:  # noqa: N807
        warnings.warn(
            DeprecationWarning(
                f"Class {old_name} was renamed, use {cls.__name__} instead"
            )
        )
        super(cast(Type, cls), self).__init__(*args, **kwargs)

    return cast(_T, type(old_name, (cls,), {"__init__": __init__}))
