"""Sphinx plugin to add references to classes and methods to left side navigation.

Functions :func:`_build_toc_node`, :func:`_find_toc_node`
and :func:`_get_toc_reference` are copied from :mod:`autoapi.toctree`.
:func:`_traverse_parent` is modified.

Credits: `sphinx-autoapi <https://github.com/readthedocs/sphinx-autoapi/>`__.
"""
import sphinx
import sphinx.util.logging
from docutils import nodes
from sphinx import addnodes
from sphinx.util.docutils import SphinxDirective

LOGGER = sphinx.util.logging.getLogger(__name__)


def _build_toc_node(docname, anchor="anchor", text="test text", bullet=False):
    """Create the node structure that Sphinx expects for TOC Tree entries.

    The ``bullet`` argument wraps it in a ``nodes.bullet_list``,
    which is how you nest TOC Tree entries.
    """
    reference = nodes.reference(
        "",
        "",
        internal=True,
        refuri=docname,
        anchorname="#" + anchor,
        *[nodes.Text(text, text)],
    )
    para = addnodes.compact_paragraph("", "", reference)
    ret_list = nodes.list_item("", para)
    return nodes.bullet_list("", ret_list) if bullet else ret_list


def _traverse_parent(node, tester):
    """Traverse up the node's parents until you hit the ``objtypes`` referenced.

    node
        Node to traverse.
    objtypes: Callable[[object], bool].
        Type to find.
    """
    curr_node = node.parent
    while curr_node is not None:
        if tester(curr_node):
            return curr_node
        curr_node = curr_node.parent
    return None


def _find_toc_node(toc, ref_id, objtype):
    """Find the actual TOC node for a ref_id.

    Depends on the object type:
    * Section - First section (refuri) or 2nd+ level section (anchorname)
    * Desc - Just use the anchor name
    """
    for check_node in toc.traverse(nodes.reference):
        if objtype == nodes.section and (
            check_node.attributes["refuri"] == ref_id
            or check_node.attributes["anchorname"] == "#" + ref_id
        ):
            return check_node
        if (
            objtype == addnodes.desc
            and check_node.attributes["anchorname"] == "#" + ref_id
        ):
            return check_node
    return None


def _get_toc_reference(node, toc, docname):
    """Get reference from map from specific node to it's part of the toctree.

    It takes a specific incoming ``node``,
    and returns the actual TOC Tree node that is said reference.
    """
    if isinstance(node, nodes.section) and isinstance(node.parent, nodes.document):
        # Top Level Section header
        ref_id = docname
        toc_reference = _find_toc_node(toc, ref_id, nodes.section)
    elif isinstance(node, nodes.section):
        # Nested Section header
        ref_id = node.attributes["ids"][0]
        toc_reference = _find_toc_node(toc, ref_id, nodes.section)
    else:
        # Desc node
        try:
            ref_id = node.children[0].attributes["ids"][0]
            toc_reference = _find_toc_node(toc, ref_id, addnodes.desc)
        except (KeyError, IndexError):
            LOGGER.warning(
                "Invalid desc node",
                exc_info=True,
                type="autoapi",
                subtype="toc_reference",
            )
            toc_reference = None

    return toc_reference


def _check_key(key, env, first_run=True):
    if key in env:
        return env[key]
    if not first_run and f"{key}.*" in env:
        return env[f"{key}.*"]
    if "." in key:
        key, _ = key.rsplit(".", 1)
        return _check_key(key, env, False)
    return None


def add_domain_to_toctree(app, doctree, docname):
    """Add domain objects to the toctree dynamically.

    This should be attached to the ``doctree-resolved`` event.
    This works by:

    * Finding each domain node (addnodes.desc)
    * Figuring out it's parent that will be in the toctree
      (nodes.section, or a previously added addnodes.desc)
    * Finding that parent in the TOC Tree based on it's ID
    * Taking that element in the TOC Tree,
      and finding it's parent that is a TOC Listing (nodes.bullet_list)
    * Adding the new TOC element for our specific node as a child
      of that nodes.bullet_list.
      This checks that bullet_list's last child,
      and checks that it is also a nodes.bullet_list,
      effectively nesting it under that element
    """
    toc = app.env.tocs[docname]
    for desc_node in doctree.traverse(addnodes.desc):
        try:
            ref_id = desc_node.children[0].attributes["ids"][0]
        except (KeyError, IndexError):
            # autodoc-style directives already add nodes to the toc.
            continue
        if _check_key(ref_id, app.env.custom_toc) is False:
            continue

        # This is the actual object that will exist in the TOC Tree
        # Sections by default, and other Desc nodes that we've previously placed.
        parent_node = _traverse_parent(
            desc_node, lambda n: isinstance(n, (addnodes.desc, nodes.section))
        )
        if not parent_node:
            continue

        toc_reference = _get_toc_reference(parent_node, toc, docname)
        if not toc_reference:
            continue

        # # Get the last child of our parent's bullet list, this is where "we" live.
        toc_insertion_point = _traverse_parent(
            toc_reference, lambda n: isinstance(n.parent, nodes.bullet_list)
        )

        try:
            # Python domain object
            ref_text = desc_node[0].attributes["fullname"].split(".")[-1].split("(")[0]
        except (KeyError, IndexError):
            # Use `astext` for other types of domain objects
            ref_text = desc_node[0].astext().split(".")[-1].split("(")[0]

        # Ensure we've added another bullet list so that we nest inside the parent,
        # not next to it
        if len(toc_insertion_point) > 1 and isinstance(
            toc_insertion_point[1], nodes.bullet_list
        ):
            to_add = _build_toc_node(docname, anchor=ref_id, text=ref_text)
            toc_insertion_point = toc_insertion_point[1]
        else:
            to_add = _build_toc_node(
                docname,
                anchor=ref_id,
                text=ref_text,
                bullet=True,
            )

        toc_insertion_point.append(to_add)


class _TocDirective(SphinxDirective):
    has_content = False

    def run(self):
        mod = self.env.ref_context.get("py:module")
        obj, _ = self.env.temp_data.get("object", [None, None])

        if not hasattr(self.env, "custom_toc"):
            self.env.custom_toc = {}

        for key in self.fmt(mod=mod, obj=obj):
            self.env.custom_toc[key] = self.include_in_toc
        return []


class _SingleTocDirective(_TocDirective):
    include_in_toc = False

    def fmt(self, mod, obj):
        return [f"{mod}.{obj}" if obj else mod]


class NoTocDirective(_SingleTocDirective):
    """Directive to exclude object and its members from sidebar nav."""

    include_in_toc = False


class ForceTocDirective(_SingleTocDirective):
    """Directive to include object and its members into sidebar nav."""

    include_in_toc = True


class _TocChildrenDirective(_TocDirective):
    optional_arguments = 1000

    def fmt(self, mod, obj):
        if self.arguments:
            return [
                (f"{mod}.{obj}.{arg}" if obj else f"{mod}.{arg}").strip(",")
                for arg in self.arguments
            ]
        else:
            return [f"{mod}.{obj}.*" if obj else f"{mod}.*"]


class NoTocChildrenDirective(_TocChildrenDirective):
    """Directive to exclude object members from sidebar nav.

    May take any number of optional arguments - concrete members to exclude.
    If no arguments are given, all members are excluded.
    """

    include_in_toc = False


class ForceTocChildrenDirective(_TocChildrenDirective):
    """Directive to include object members into sidebar nav.

    May take any number of optional arguments - concrete members to include.
    If no arguments are given, all members are included.
    """

    include_in_toc = True


def setup(app):
    """Set up this module as a sphinx extension."""
    app.add_directive("customtox-exclude", NoTocDirective)
    app.add_directive("customtox-exclude-children", NoTocChildrenDirective)
    app.add_directive("customtox-include", ForceTocDirective)
    app.add_directive("customtox-include-children", ForceTocChildrenDirective)

    app.connect("doctree-resolved", add_domain_to_toctree)

    return {"version": sphinx.__display_version__, "parallel_read_safe": True}
