"""Required only to allow editable installs."""
import sys

if sys.version_info < (3, 7):
    import ppsetuptools

    ppsetuptools.setup()
else:
    import setuptools

    setuptools.setup()
