from cry import black2b256
from cry import keccak256
from cry import is_address
from cry import to_checksum_address

if __name__ == "__main__":
    h, _ = black2b256([b'hello world'])
    assert h.hex() == '256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610'

    h, _ = black2b256([b'hello', b' world'])
    assert h.hex() == '256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610'

    h, _ = keccak256([b'hello world'])
    assert h.hex() == '47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad'

    h, _ = keccak256([b'hello', b' world'])
    assert h.hex() == '47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad'
    
    #TODO test public_key_to_address

    address = [
        '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
        '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
        '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
        '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'
    ]

    for addr in address:
        assert is_address(addr)
        assert to_checksum_address(addr) == addr
