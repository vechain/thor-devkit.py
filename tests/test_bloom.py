from thor_devkit import Bloom


def test_estimate():
    assert Bloom.estimate_k(1) == 16
    assert Bloom.estimate_k(100) == 14
    assert Bloom.estimate_k(200) == 7
    assert Bloom.estimate_k(300) == 5
    assert Bloom.estimate_k(400) == 4
    assert Bloom.estimate_k(500) == 3


def test_add():
    b = Bloom(14)
    b.add(bytes("hello world", "UTF-8"))
    assert b.bits.hex() == (
        "0" * 51
        + "4"
        + "0" * 153
        + "1"
        + "0" * 11
        + "4"
        + "0" * 19
        + "4"
        + "0" * 91
        + "1"
        + "0" * 16
        + "1"
        + "0" * 13
        + "2"
        + "0" * 27
        + "8"
        + "0" * 31
        + "8"
        + "0" * 7
        + "1"
        + "0" * 21
        + "4002"
        + "0" * 11
        + "8"
        + "0" * 20
        + "8"
        + "0" * 25
    )


def test_test():
    b = Bloom(14)
    for i in range(100):
        b.add(bytes(str(i), "UTF-8"))

    for i in range(100):
        assert b.test(bytes(str(i), "UTF-8"))
