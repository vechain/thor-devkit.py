Installation
============

You can install ``thor_devkit`` with ``pip``:

.. code-block:: bash

	pip install thor-devkit -U

.. warning::

	`Bip32 library <https://github.com/darosior/python-bip32>`__ depends on the ``ripemd160`` hash library, which should be present on your system (on Linux it is part of `openssl <https://www.openssl.org/source/>`__).

Installing from source:

.. code-block:: bash

	git clone https://github.com/vechain/thor_devkit.py
	cd thor_devkit.py
	pip install .


Supported extras:

- ``test``: install developer requirements (``pip install thor-devkit[test]``).
- ``docs``: install ``sphinx``-related packages (``pip install thor-devkit[test,docs]``).
