import pytest


@pytest.fixture()
def dyn_prefix():
    return bytes.fromhex("20".rjust(64, "0"))
