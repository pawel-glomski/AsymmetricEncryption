import json
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP


def encryptCTR(public_key_string, data):
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


def decryptCTR(private_key_string, json_data):
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


def generate_keys(public_path, private_path, password=None):
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()

    with open(public_path, 'wb') as f:
        f.write(public_key.export_key())

    with open(private_path, 'wb') as f:
        if password == None:
            f.write(private_key.export_key())
        else:
            f.write(private_key.export_key(passphrase=password))


# jesli zle haslo zwraca None, inaczej krotke kluczy (RSA Key object)
# only one: 0 - zaladuj oba, 1 - zaladuj tylko publiczny, 2 - zaladuj tylko prywatny
def load_keys(public_path, private_path, password=None):
    with open(public_path, 'r') as f:
        public_key = RSA.import_key(f.read())

    with open(private_path, 'r') as f:
        try:
            if password == None:
                private_key = RSA.importKey(f.read())
            else:
                private_key = RSA.importKey(f.read(), passphrase=password)
        except:
            return None

    return (public_key, private_key)
