import warnings
from functools import partial, wraps
from typing import Any, Callable, Type, TypeVar, cast

_C = TypeVar("_C", bound=Callable[..., Any])
_T = TypeVar("_T")


def deprecated_to_property(func: _C) -> _C:
    @wraps(func)
    def inner(*args: Any, **kwargs: Any) -> Any:
        warnings.warn(
            DeprecationWarning("This method is deprecated, use property instead")
        )
        return func(*args, **kwargs)

    return cast(_C, inner)


def class_renamed(cls: Type[_T], old_name: str) -> Type[_T]:
    def __init__(self: _T, *args: Any, **kwargs: Any) -> None:  # noqa: N807
        warnings.warn(
            DeprecationWarning(
                f"Class {old_name} was renamed, use {cls.__name__} instead"
            )
        )
        super(cast(Type[Any], cls), self).__init__(*args, **kwargs)

    return cast(Type[_T], type(old_name, (cls,), {"__init__": __init__}))


def _renamed_function(new_name: str, kind: str) -> Callable[[_C], _C]:
    def decorator(func: _C) -> _C:
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
