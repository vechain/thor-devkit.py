"""Configuration file for the Sphinx documentation builder."""
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.resolve()))

from ext.monkey_patch_sphinx import monkey_patch  # noqa: E402  # We need new PATH here.

monkey_patch()


# -- Project information -----------------------------------------------------

project = "thor-devkit.py"
copyright = "2022, laalaguer"  # noqa: A001
author = "laalaguer"

release = "2.0.0"


# -- General configuration ---------------------------------------------------

extensions = [
    # Built-in plugins
    "sphinx.ext.napoleon",  # Numpy-style docstring preprocessing
    "sphinx.ext.autodoc",  # Docstring embedding into final documents
    "sphinx.ext.intersphinx",  # References to stl
    "sphinx.ext.graphviz",  # Nice visual diagrams representation
    "sphinx.ext.viewcode",  # Links to source
    # Third-party
    "autodocsumm",  # Table of module/class elements
    # Custom
    "ext.toc_plugin",  # Add items to left floating table of contents
    "ext.types_group",  # Separate group for type definitions and validation schemas
    "ext.monkey_patch_sphinx",  # Fix up ``dict`` as ``TypedDict`` base after all.
]

templates_path = ["_templates"]
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]

# -- Autodoc config ----------------------------------------------------------

autoclass_content = "both"
autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
    "autosummary": True,
    "autosummary-members": True,
    "autosummary-undoc-members": True,
    "autosummary-nosignatures": True,
    "member-order": "bysource",
}

intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
    "voluptuous": ("http://alecthomas.github.io/voluptuous/docs/_build/html/", None),
    "bip_utils": ("https://bip-utils.readthedocs.io/en/latest/", None),
    "solcx": ("https://solcx.readthedocs.io/en/latest/", None),
}
