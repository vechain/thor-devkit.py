'''
Keystore

encrypt, decrypt and verify a keystore file.
'''

import eth_keyfile

N = 131072  # aka. work_factor
P = 1
R = 8
DK_LEN = 32
SALT_LEN = 16


def encrypt(private_key: bytes, password: bytes) -> dict:
    '''
    Encrypt a private key to a keystore.
    The keystore is a json-style python dict.

    Args:
        private_key: A private key in bytes.
        password: A password.

    Returns:
        (dict): A keystore, a json-style dict object.
    '''
    return eth_keyfile.create_keyfile_json(private_key, password, 3, "scrypt", N)


def decrypt(keystore: dict, password: bytes) -> bytes:
    '''
    Decrypt a keystore into a private key (bytes).

    Args:
        keystore: A json-style dict.
        password: A password.

    Returns:
        (bytes): A private key in bytes.
    '''
    return eth_keyfile.decode_keyfile_json(keystore, password)

# def normalize(keystore: dict) -> dict:
#     '''
#     Normalize the keystore key:value pairs.
#     Make each value in lower case.
#     '''
#     pass


# def validate(keystore: dict) -> bool:
#     '''
#     Validate the format of a key store.

#     Returns:
#         (bool): True/False
#     '''
#     pass
