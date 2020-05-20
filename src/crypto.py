import json
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP


def encryptCTR(public_key_string, data):
    public_key = RSA.import_key(public_key_string)

    sync_key = get_random_bytes(32)
    cipher = AES.new(sync_key, AES.MODE_CTR)
    cipher_data = cipher.encrypt(data)
    nonce = cipher.nonce

    encryptor = PKCS1_OAEP.new(public_key)
    encrypted_key = encryptor.encrypt(sync_key)

    json_result = json.dumps({'nonce': b64encode(nonce).decode('utf-8'), 'encrypted_key': b64encode(
        encrypted_key).decode('utf-8'), 'cipher_data': b64encode(cipher_data).decode('utf-8')})

    return json_result


def decryptCTR(private_key_string, json_data):
    private_key = RSA.import_key(private_key_string)
    nonce = b64decode(json_data['nonce'])
    cipher_data = b64decode(json_data['cipher_data'])
    encrypted_key = b64decode(json_data['encrypted_key'])

    decryptor = PKCS1_OAEP.new(private_key)
    sync_key = decryptor.decrypt(encrypted_key)

    cipher = AES.new(sync_key, AES.MODE_CTR, nonce=nonce)
    decrypted_data = cipher.decrypt(cipher_data)

    return decrypted_data
