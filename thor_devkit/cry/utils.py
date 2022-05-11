"""Utils helping with ``hex <-> string`` conversion and stripping."""
import sys
from functools import partial
from typing import TYPE_CHECKING, Any, Callable, Type, TypeVar, cast

from thor_devkit.deprecation import renamed_function

if sys.version_info < (3, 8):
    from typing_extensions import Literal
else:
    from typing import Literal


def _strict_zip(*iterables):  # type: ignore[no-untyped-def]
    iterators = [iter(it) for it in iterables]
    yield from zip(*iterators)
    for i, it in enumerate(iterators):
        try:
            next(it)
        except StopIteration:
            pass
        else:
            raise ValueError(f"izip argument {i} was longer than some other.")


if TYPE_CHECKING:
    # We don't have variadic generics yet (see PEP646, unsupported by mypy).
    # Convince mypy that this is :func:`zip` itself.
    izip = zip
    r"""Implements ``python3.10+`` zip strict mode.

    In python 3.10 and higher it is an alias for ``partial(zip, strict=True)``.

    :meta hide-value:

    Parameters
    ----------
    \*iterables: Iterable[Any]
        Iterables to zip together.

    Yields
    ------
    Tuple[Any, ...]
        Tuples of values like standard :func:`zip` generates.

    Raises
    ------
    ValueError
        If not all iterables had equal length.
    """
elif sys.version_info < (3, 10):
    izip = _strict_zip
else:
    izip = partial(zip, strict=True)


def strip_0x04(p: bytes) -> bytes:
    """Strip the ``0x04`` off the starting of a byte sequence."""
    if len(p) == 65 and p[0] == 4:
        return p[1:]
    else:
        return p


def remove_0x(address: str) -> str:
    """Remove the ``0x`` prefix if any.

    Parameters
    ----------
    address : str
        Address string, like ``0xabc``...

    Returns
    -------
    str
        Address string without prefix ``0x``
    """
    if address.startswith("0x") or address.startswith("0X"):
        return address[2:]
    else:
        return address


def validate_uncompressed_public_key(key_bytes: bytes) -> Literal[True]:
    """Check if bytes is the uncompressed public key.

    Parameters
    ----------
    key_bytes : bytes
        Address in bytes.

    Returns
    -------
    Literal[True]
        Always ``True`` if public key is valid, raises otherwise.

    Raises
    ------
    ValueError
        If address doesn't begin with ``04`` as first byte.
    """
    if len(key_bytes) != 65:
        raise ValueError("Length should be 65 bytes.")

    if key_bytes[0] != 4:
        raise ValueError("Should begin with 04 as first byte.")

    return True


def is_valid_uncompressed_public_key(key_bytes: bytes) -> bool:
    """Check if bytes is the uncompressed public key.

    Parameters
    ----------
    key_bytes : bytes
        Address in bytes.

    Returns
    -------
    bool
        Whether input is uncompressed public key.
    """
    try:
        return validate_uncompressed_public_key(key_bytes)
    except ValueError:
        return False


@renamed_function("validate_uncompressed_public_key")
def is_uncompressed_public_key(key_bytes: bytes) -> Literal[True]:
    """Check if bytes is the uncompressed public key.

    .. customtox-exclude::

    .. deprecated:: 2.0.0
        Use :func:`is_valid_uncompressed_public_key` or
        :func:`validate_uncompressed_public_key` instead.
    """
    return validate_uncompressed_public_key(key_bytes)


_T = TypeVar("_T")


def safe_tolowercase(s: _T) -> _T:
    """Lowercase input if it is string, return unchanged otherwise.

    Parameters
    ----------
    s : str or Any
        Value to process.

    Returns
    -------
    str or Any
        Lowercase value if it is a string, value unchanged otherwise.
    """
    if isinstance(s, str):
        # Cast, because mypy doesn't resolve TypeVar inside function body
        return cast(_T, s.lower())
    else:
        return s


_Class = TypeVar("_Class", bound=Type[Any])


def _with_doc_mro(*bases: Type[Any]) -> Callable[[_Class], _Class]:
    r"""Internal function for documentation enhancement.

    Designed use case: ``sphinx.ext.autosummary`` doesn't play well
    with inheritance of :class:`~typing.TypedDict`. It throws errors
    for every parent-defined key. This helper (and monkey-patching module,
    of course) allows to overcome this.

    Parameters
    ----------
    \*bases : Type[Any]
        Classes you inherit from (and their parents, optionally).

        Attributes of these (and only these) classes will be documented.

    Returns
    -------
    Callable[[_Class], _Class]
        Class decorator.

    Note
    ----
    The reason behind that is the implementation of :class:`~typing.TypedDict`.
    It does not include parents into __mro__, for every typed dict::

        __mro__ = (<This class>, dict, object)

    This behaviour does not allow ``autodoc`` and ``autosummary`` process
    members properly. We set special ``__doc_mro__`` attribute and read it
    when building MRO for documentation.
    """

    def wrapper(cls: _Class) -> _Class:
        cls.__doc_mro__ = (cls, *bases)
        return cls

    return wrapper
