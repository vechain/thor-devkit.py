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
        "0000000000000000000000000000000000000000000000000004000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000100000000000400000000000000000004000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000001000000000000000010000000000000200000000000000000000000"
        "0000800000000000000000000000000000008000000010000000000000000000"
        "0040020000000000080000000000000000000080000000000000000000000000"
    )


def test_test():
    b = Bloom(14)
    for i in range(100):
        b.add(str(i).encode())

    for i in range(100):
        assert b.test(str(i).encode())
        assert str(i).encode() in b

    for i in range(100, 200):
        assert not b.test(str(i).encode())
        assert str(i).encode() not in b


def test_inherit():
    b = Bloom(14)
    for i in range(50):
        b.add(str(i).encode())

    new_b = Bloom(14, b.bits)
    for i in range(50, 100):
        new_b.add(str(i).encode())

    for i in range(100):
        assert new_b.test(str(i).encode())

    for i in range(100, 200):
        assert not new_b.test(str(i).encode())
