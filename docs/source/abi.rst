ABI encoding
============

Basic concepts
--------------

Function selector
*****************

Function selector is computed as first 4 bytes of::

   sha3(signature)

where ``signature`` is of form ``funcName(uint8,bool,string)`` (types of arguments
in parentheses) and must not contain any whitespace. All types are normalized
to standard form (e.g. ``fixed`` is transformed into ``fixed128x18`` before hashing).

Supported types
***************

.. table:: Supported types for argument encoding
   :width: 100%

   +---------------------+-----------------------------------------------------------+
   |    Type             |                      Description                          |
   +=====================+===========================================================+
   |                                  **Elementary types**                           |
   +---------------------+-----------------------------------------------------------+
   | | ``uint<M>``       | | Unsigned and signed ``M``-bit integer.                  |
   | | ``int<M>``        | | :math:`0 < M \leq 256`,                                 |
   |                     |   :math:`M \equiv 0 \pmod 8`                              |
   +---------------------+-----------------------------------------------------------+
   | ``address``         | Synonym for ``uint160`` with special semantical meaning.  |
   +---------------------+-----------------------------------------------------------+
   | | ``int``           | | Synonyms for ``int256`` and ``uint256``                 |
   | | ``uint``          | | Normalized to full form when computing selector.        |
   +---------------------+-----------------------------------------------------------+
   | ``bool``            | Equivalent to ``uint8``, restricted to ``0`` or ``1``     |
   +---------------------+-----------------------------------------------------------+
   | | ``fixed<M>x<N>``  | | Signed (unsigned) fixed-point ``M``-bit number          |
   |                     | | such that number :math:`x` represents value             |
   |                     |   :math:`\left\lfloor \frac{x}{10^N} \right\rfloor`       |
   | | ``ufixed<M>x<N>`` | | :math:`0 < M \leq 256`, :math:`0 < N \leq 80`,          |
   |                     |   :math:`M \equiv N \equiv 0 \pmod 8`                     |
   +---------------------+-----------------------------------------------------------+
   | | ``fixed``         | | Synonyms for ``fixed128x18`` and ``fixed128x18``        |
   | | ``ufixed``        | | Normalized to full form when computing selector.        |
   +---------------------+-----------------------------------------------------------+
   |``bytes<M>``         | Sequence of ``M`` bytes.                                  |
   +---------------------+-----------------------------------------------------------+
   |``function``         | Synonym of ``bytes24``.                                   |
   |                     | 20 bytes address + 4 bytes signature.                     |
   +---------------------+-----------------------------------------------------------+
   |                                **Fixed-length types**                           |
   +---------------------+-----------------------------------------------------------+
   | ``<type>[M]``       | | Fixed sized array of type ``<type>``.                   |
   |                     | | Examples: ``int[10]``, ``uint256[33]``                  |
   +---------------------+-----------------------------------------------------------+
   |                                  **Dynamic types**                              |
   +---------------------+-----------------------------------------------------------+
   | ``bytes``           | Bytes of arbitrary length.                                |
   +---------------------+-----------------------------------------------------------+
   | ``string``          | String of arbitrary length.                               |
   +---------------------+-----------------------------------------------------------+
   | ``<type>[]``        | Array of ``<type>`` of arbitrary length.                  |
   +---------------------+-----------------------------------------------------------+

Further reading
***************

`Specification <https://docs.soliditylang.org/en/develop/abi-spec.html>`_

API documentation
-----------------

.. automodule:: thor_devkit.abi
   :inherited-members: dict
