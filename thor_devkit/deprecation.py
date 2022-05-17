"""Deprecation helpers."""
import warnings
from functools import partial, wraps
from typing import Any, Callable, Type, TypeVar, cast

_C = TypeVar("_C", bound=Callable[..., Any])
_T = TypeVar("_T")


def deprecated_to_property(func: _C) -> _C:
    """Mark function as deprecated in favor of property."""
    assert not func.__doc__ or ".. deprecated::" in func.__doc__

    @wraps(func)
    def inner(*args: Any, **kwargs: Any) -> Any:
        warnings.warn(
            DeprecationWarning("This method is deprecated, use property instead")
        )
        return func(*args, **kwargs)

    return cast(_C, inner)


def renamed_class(new_name: str) -> Callable[[Type[_T]], Type[_T]]:
    """Mark class as renamed."""

    def decorator(cls: Type[_T]) -> Type[_T]:
        assert not cls.__doc__ or ".. deprecated::" in cls.__doc__

        def __init__(self: _T, *args: Any, **kwargs: Any) -> None:  # noqa: N807
            warnings.warn(
                DeprecationWarning(
                    f"Class {cls.__name__} was renamed, use {new_name} instead"
                )
            )
            super(cls, self).__init__(*args, **kwargs)  # type: ignore

        cls.__init__ = __init__  # type: ignore
        return cls

    return decorator


def _renamed_function(new_name: str, kind: str) -> Callable[[_C], _C]:
    """Mark function or method as renamed."""

    def decorator(func: _C) -> _C:
        assert not func.__doc__ or ".. deprecated::" in func.__doc__

        @wraps(func)
        def inner(*args: Any, **kwargs: Any) -> Any:
            warnings.warn(
                DeprecationWarning(
                    f"{kind} {func.__name__} is deprecated. Use {new_name} instead."
                )
            )
            return func(*args, **kwargs)

        return cast(_C, inner)

    return decorator


renamed_function = partial(_renamed_function, kind="Function")
renamed_method = partial(_renamed_function, kind="Method")


def deprecated(obj: _T) -> _T:
    """Marker for anything deprecated for another reasons."""
    assert not getattr(obj, "__doc__", "") or ".. deprecated::" in str(obj.__doc__)
    return obj
