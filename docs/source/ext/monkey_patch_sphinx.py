"""Monkey patch :mod:`sphinx` to play well with specific inheritance.

We set __doc_mro__ attribute for classes that should be altered.

Then :func:`sphinx.util.inspect.getmro` is patched to honor this attribute.

Finally, :mod:`sphinx.ext.autosummary` does not read inherited variable members,
so we patch it too to use our brand-new ``getmro``.
"""
from typing import TypedDict, is_typeddict

from sphinx.util import inspect

old_getmro = inspect.getmro


def new_getmro(obj):
    """Try to extract ``__doc_mro__`` attribute, fallback to default behavior."""
    doc_mro = getattr(obj, "__doc_mro__", None)
    if isinstance(doc_mro, tuple):
        return doc_mro

    return old_getmro(obj)


def new_import_ivar_by_name(
    name,
    prefixes=[None],  # noqa: B006  # It is not my decision!
    grouped_exception=False,
):
    """Get instance variables, including parents traversing."""
    from sphinx.ext import autosummary as asum

    # This is original source
    try:
        name, attr = name.rsplit(".", 1)
        real_name, obj, parent, modname = asum.import_by_name(
            name, prefixes, grouped_exception
        )
        qualname = real_name.replace(modname + ".", "")
        analyzer = asum.ModuleAnalyzer.for_module(getattr(obj, "__module__", modname))
        analyzer.analyze()
        if (
            (qualname, attr) in analyzer.attr_docs
            # check for presence in `annotations` to include dataclass attributes
            or (qualname, attr) in analyzer.annotations
        ):
            return real_name + "." + attr, asum.INSTANCEATTR, obj, modname
    except (ImportError, ValueError, asum.PycodeError) as exc:
        raise ImportError from exc
    except asum.ImportExceptionGroup:
        raise  # pass through it as is

    # ===================== Added part ==============================================
    # Try to resolve instance-level variables by MRO, if they were requested.
    for base in new_getmro(obj):
        qname = getattr(base, "__qualname__", None) or getattr(base, "__name__", None)
        if not qname:
            continue
        if (qname, attr) in analyzer.attr_docs or (qname, attr) in analyzer.annotations:
            mname = getattr(base, "__module__", modname)
            return f"{mname}.{qname}.{attr}", asum.INSTANCEATTR, base, modname
    # ===============================================================================

    # Fail as before, if no success.
    raise ImportError


def monkey_patch():
    """Script entry point."""
    inspect.getmro = new_getmro

    from sphinx.ext import autosummary

    autosummary._module.import_ivar_by_name = new_import_ivar_by_name


def fix_typeddict_bases(app, name, obj, options, bases):
    """Fix ``dict`` display for ``TypedDict``."""
    if is_typeddict(obj):
        bases[:] = [TypedDict]


def setup(app):
    """Set up this extension."""
    app.connect("autodoc-process-bases", fix_typeddict_bases)
