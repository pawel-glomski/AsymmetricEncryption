import json
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP


def encrypt(public_key_string, data):
    public_key = RSA.import_key(public_key_string)

    sync_key = get_random_bytes(32)  # liczba bajtow do ustalenia
    cipher = AES.new(sync_key, AES.MODE_CTR)
    cipher_data = cipher.encrypt(data)
    nonce = cipher.nonce

    encryptor = PKCS1_OAEP.new(public_key)
    encrypted_key = encryptor.encrypt(sync_key)

    json_result = json.dumps({'nonce': b64encode(nonce).decode('utf-8'), 'encrypted_key': b64encode(
        encrypted_key).decode('utf-8'), 'cipher_data': b64encode(cipher_data).decode('utf-8')})

    return json_result


def decrypt(private_key_string, json_data):
    private_key = RSA.import_key(private_key_string)
    b64 = json.loads(json_data)
    nonce = b64decode(b64['nonce'])
    cipher_data = b64decode(b64['cipher_data'])
    encrypted_key = b64decode(b64['encrypted_key'])

    decryptor = PKCS1_OAEP.new(private_key)
    sync_key = decryptor.decrypt(encrypted_key)

    cipher = AES.new(sync_key, AES.MODE_CTR, nonce=nonce)
    decrypted_data = cipher.decrypt(cipher_data)

    return decrypted_data


key = RSA.generate(2048)
public_key_string = key.publickey().export_key()
data = b'abcde'

json_result = encrypt(public_key_string, data)

decrypted_data = decrypt(key.export_key(), json_result)
print(decrypted_data)

# data = b'abcdefgb'
# sync_key = get_random_bytes(16)

# cipher = AES.new(sync_key, AES.MODE_CTR)
# ciphertext = cipher.encrypt(data)
# nonce = cipher.nonce

#cryptor = PKCS1_OAEP.new(key)
#encrypted_key = cryptor.decrypt(crypted_key)

#decrypted_key = cryptor.decrypt(encrypted_key)

#print(decrypted_key, sync_key)
