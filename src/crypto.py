import json
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import os
import mmap


def encryptCTR(public_key_string, data_path, ouput_path, chunkSize=64*1024):
    public_key = RSA.import_key(public_key_string)

    sync_key = get_random_bytes(32)
    cipher = AES.new(sync_key, AES.MODE_CTR)
    # cipher_data = cipher.encrypt(data)
    nonce = cipher.nonce

    encryptor = PKCS1_OAEP.new(public_key)
    encrypted_key = encryptor.encrypt(sync_key)

    json_header = json.dumps({'nonce': b64encode(nonce).decode('utf-8'), 'encrypted_key': b64encode(
        encrypted_key).decode('utf-8')})

    encryptToFile(data_path, json_header, ouput_path, cipher, chunkSize)


def encryptToFile(data_path, header, output_path, cipher, chunkSize):
    with open(output_path, 'w') as fo:
        fo.write(header)
        fo.write('\n')

    with open(data_path, 'rb') as fi:
        with open(output_path, 'ab') as fo:
            while True:
                chunk = fi.read(chunkSize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))
                fo.write(cipher.encrypt(chunk))


def decryptCTR(private_key_string, data_path, ouput_path, chunkSize=64*1024):
    private_key = RSA.import_key(private_key_string)

    with open(data_path, 'rb') as f:  # read header
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as stream:
            data_offset = stream.find(b'}') + 2
            jsonStr = f.read(stream.find(b'}') + 2)
            header_json = json.loads(jsonStr)

    nonce = b64decode(header_json['nonce'])
    encrypted_key = b64decode(header_json['encrypted_key'])

    decryptor = PKCS1_OAEP.new(private_key)
    sync_key = decryptor.decrypt(encrypted_key)

    cipher = AES.new(sync_key, AES.MODE_CTR, nonce=nonce)
    # decrypted_data = cipher.decrypt(cipher_data)
    decryptToFile(data_path, ouput_path, cipher, data_offset, chunkSize)


def decryptToFile(data_path, output_path, cipher, data_offset, chunkSize):
    with open(data_path, 'rb') as fi:
        fi.seek(data_offset)
        with open(output_path, 'wb') as fo:
            while True:
                chunk = fi.read(chunkSize)
                if len(chunk) == 0:
                    break
                fo.write(cipher.decrypt(chunk))


def saveHeader(file, mode, filesize, IV):
    file.write(str(len(mode)).zfill(16).encode('utf-8'))
    file.write(mode.zfill(16).encode('utf-8'))
    file.write(filesize.encode('utf-8'))
    file.write(IV)


def loadHeader(file):
    modeLength = int(file.read(16))
    mode = file.read(16).decode('utf-8')
    mode = mode[-modeLength:]
    filesize = int(file.read(16))
    IV = file.read(16)
    return mode, filesize, IV


def AESencryptCBC(key, filename, outputFilename, chunkSize=64*1024):
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = get_random_bytes(16)
    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as fi:
        with open(outputFilename, 'wb') as fo:
            mode = 'CBC'
            saveHeader(fo, mode, filesize, IV)
            while True:
                chunk = fi.read(chunkSize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))
                fo.write(encryptor.encrypt(chunk))


def AESdecryptCBC(key, filename, outputFilename, chunkSize=64*1024):
    with open(filename, 'rb') as fi:
        _, filesize, IV = loadHeader(fi)
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        with open(outputFilename, 'wb') as fo:
            while True:
                chunk = fi.read(chunkSize)
                if len(chunk) == 0:
                    break
                fo.write(decryptor.decrypt(chunk))
            fo.truncate(filesize)


def AESdecrypt(key, filename, outputFilename, chunkSize=64*1024):
    with open(filename, 'rb') as fi:
        mode, _, __ = loadHeader(fi)
    if mode == 'CBC':
        AESdecryptCBC(key, filename, outputFilename, chunkSize=64*1024)
    else:
        print('Unknown mode: '+mode)
