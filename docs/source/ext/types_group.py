"""Sphinx plugin to extract separate group with type aliases and validation helpers."""
import sys

import sphinx
from voluptuous import Schema

if sys.version_info < (3, 10):
    from typing_extensions import is_typeddict
else:
    from typing import is_typeddict


def guess_group(app, what, name, obj, section, parent):
    """Extract separate group with type aliases and validation helpers."""
    if (
        # We can use TypedDict for static validation
        is_typeddict(obj)
        # :mod:`voluptuous` for dynamic validation
        or isinstance(obj, Schema)
        # or declare type alias.
        or obj.__class__.__module__ in {"typing", "typing_extensions"}
    ):
        return "Type or structure checkers"


def skip_member(app, what, name, obj, skip, options):
    """Keep documenting deprecated methods (they are not in __all__).

    As side effect this moves deprecated stuff to the end of module/class,
    which is desired behaviour.
    """
    if "deprecated::" in (obj.__doc__ or ""):
        return False


def setup(app):
    """Set up this module as a sphinx extension."""
    app.connect("autodocsumm-grouper", guess_group)
    app.connect("autodoc-skip-member", skip_member)

    return {"version": sphinx.__display_version__, "parallel_read_safe": True}
