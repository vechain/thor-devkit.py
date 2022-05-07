RLP encoding
============

RLP (**r**\ ecursive **l**\ ength **p**\ refix) is a common algorithm for encoding
of variable length binary data. RLP encodes data before storing on disk
or transmitting via network.

Theory
------

Encoding
********

Primary RLP can only deal with "item" type, which is defined as:

#. Byte string (:class:`bytes` or :class:`bytearray` in Python) or
#. Sequence of items (usually :class:`list`).

Some examples are:

* ``b'\x00\xff'``
* empty list ``[]``
* list of bytes ``[b'\x00', b'\x01\x03']``
* list of combinations ``[[], b'\x00', [b'\x00']]``

The encoded result is always a byte string:

.. graphviz::
   :caption: RLP encoding diagram
   :alt: RLP encoding diagram
   :align: center

   digraph RLP_basic {
      rankdir="LR";
      item [shape="box", label="Item"];
      rlp [shape="box", label="RLP"];
      item -> rlp [label="Encoding"];
   }

Encoding algorithm
******************

Given ``x`` item as input, we define ``rlp_encode`` as the following algorithm:

    Let ``concat`` be a function that joins given bytes into single byte sequence.

    #. If ``x`` is a single byte and ``0x00 <= x <= 0x7F``, ``rlp_encode(x) = x``.

    #. Otherwise, if ``x`` is a byte string, Let ``len(x)`` be length of ``x`` in bytes
       and define encoding as follows:

       * If ``0 < len(x) < 0x38``
         (note that empty byte string fulfills this requirement, as well as ``b'0x80``)::

            rlp_encode(x) = concat(0x80 + len(x), x)

         In this case first byte is in range ``[0x80; 0xB7]``.

       * If ``0x38 <= len(x) <= 0xFFFFFFFF``::

            rlp_encode(x) = concat(0xB7 + len(len(x)), len(x), x)

         In this case first byte is in range ``[0xB8; 0xBf]``.

       * For longer strings encoding is ``undefined``.

    #. Otherwise, if ``x`` is a list, let ``s = concat(map(rlp_encode, x))``
       be concatenation of RLP encodings of all its items.

       * If ``0 < len(s) < 0x38`` (note that empty list matches)::

            rlp_encode(x) = concat(0xC0 + len(s), s)

         In this case first byte is in range ``[0xC0; 0xF7]``.

       * If ``0x38 <= len(s) <= 0xFFFFFFFF``::

            rlp_encode(x) = concat(0xF7 + len(len(s)), len(s), x)

         In this case first byte is in range ``[0xF8; 0xFF]``.

       * For longer lists encoding is ``undefined``.

See more in `Ethereum wiki <https://eth.wiki/fundamentals/rlp>`__.

Encoding examples
*****************

.. table:: Encoding examples
    :width: 100%

    +-------------------+--------------------------------+
    | ``x``             |       ``rlp_encode(x)``        |
    +===================+================================+
    | ``b''``           | ``0x80``                       |
    +-------------------+--------------------------------+
    | ``b'\x00'``       | ``0x00``                       |
    +-------------------+--------------------------------+
    | ``b'\x0F'``       | ``0x0F``                       |
    +-------------------+--------------------------------+
    | ``b'\x79'``       | ``0x79``                       |
    +-------------------+--------------------------------+
    | ``b'\x80'``       | ``0x81 0x80``                  |
    +-------------------+--------------------------------+
    | ``b'\xFF'``       | ``0x81 0xFF``                  |
    +-------------------+--------------------------------+
    | ``b'foo'``        | ``0x83 0x66 0x6F 0x6F``        |
    +-------------------+--------------------------------+
    | ``[]``            | ``0xC0``                       |
    +-------------------+--------------------------------+
    | ``[b'\x0F']``     | ``0xC1 0x0F``                  |
    +-------------------+--------------------------------+
    | ``[b'\xEF']``     | ``0xC1 0x81 0xEF``             |
    +-------------------+--------------------------------+
    | ``[[], [[]]]``    | ``0xC3 0xC0 0xC1 0xC0``        |
    +-------------------+--------------------------------+


Serialization
*************

However, in the real world, the inputs are not pure bytes nor lists.
Some are of complex key-value pairs like :class:`dict`.
Some are of ``"0x123"`` form of number.

This module exists for some pre-defined
``real world object => "item"`` conversion, *serialization*:

.. graphviz::
    :caption: Actual RLP encoding diagram
    :alt: Actual RLP encoding diagram
    :align: center

    digraph RLP_basic {
        rankdir="LR";
        item [shape="box", label="Item"];
        obj [shape="box", label="Real world\nobject"]
        rlp [shape="box", label="RLP"];
        obj -> item [label="Serialization"]
        item -> rlp [label="Encoding"];
    }

API documentation
-----------------

.. automodule:: thor_devkit.rlp
    :autosummary-no-nesting:
