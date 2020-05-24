import json
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import os
import mmap


EncryptedDataLabel = b'encrypted_file:'


def makeCipher(encModeStr: str, sym_key: bytes, filesize, initBytes=None):
    mode = getattr(AES, 'MODE_'+encModeStr)
    if mode == AES.MODE_CCM:
        filesize += 100
        return AES.new(sym_key, mode, nonce=initBytes, msg_len=filesize)
    if initBytes is None:
        return AES.new(sym_key, mode)
    if hasattr(AES.new(sym_key, mode), 'nonce'):
        return AES.new(sym_key, mode, nonce=initBytes)
    return AES.new(sym_key, mode, initBytes)  # iv


def makeHeader(cipher, sym_key: bytes, encModeStr: str, public_key_string: str, filesize: int) -> str:
    initBytes = cipher.nonce if hasattr(cipher, 'nonce') else cipher.iv
    encrypted_key = PKCS1_OAEP.new(
        RSA.import_key(public_key_string)).encrypt(sym_key)
    return json.dumps({'initBytes': b64encode(initBytes).decode('utf-8'),
                       'encrypted_key':  b64encode(encrypted_key).decode('utf-8'),
                       'mode': encModeStr,
                       'filesize': filesize})


def encrypt(encModeStr, public_key_string, data_path, ouput_path, chunkSize=64*1024):
    sym_key = get_random_bytes(32)
    filesize = os.path.getsize(data_path)
    cipher = makeCipher(encModeStr, sym_key, filesize)
    json_header = makeHeader(cipher, sym_key, encModeStr,
                             public_key_string, filesize)
    encryptToFile(data_path, json_header, ouput_path, cipher, chunkSize)


def encryptToFile(data_path, header, output_path, cipher, chunkSize):
    with open(output_path, 'w') as fo:
        fo.write(header)
        fo.write(EncryptedDataLabel.decode('ascii'))

    with open(data_path, 'rb') as fi:
        with open(output_path, 'ab') as fo:
            while True:
                chunk = fi.read(chunkSize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))
                fo.write(cipher.encrypt(chunk))


def decrypt(private_key_string, data_path, ouput_path, chunkSize=64*1024):
    private_key = RSA.import_key(private_key_string)

    with open(data_path, 'rb') as f:  # read header
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as stream:
            header_json = json.loads(f.read(stream.find(b'}') + 1))
            data_offset = stream.find(
                EncryptedDataLabel) + len(EncryptedDataLabel)

    initBytes = b64decode(header_json['initBytes'])
    encrypted_key = b64decode(header_json['encrypted_key'])
    encModeStr = header_json['mode']
    filesize = int(header_json['filesize'])

    sym_key = PKCS1_OAEP.new(private_key).decrypt(encrypted_key)

    cipher = makeCipher(encModeStr, sym_key, filesize, initBytes)
    decryptToFile(data_path, ouput_path, cipher,
                  data_offset, filesize, chunkSize)


def decryptToFile(data_path, output_path, cipher, data_offset, filesize, chunkSize):
    with open(data_path, 'rb') as fi:
        fi.seek(data_offset)
        with open(output_path, 'wb') as fo:
            while True:
                chunk = fi.read(chunkSize)
                if len(chunk) == 0:
                    break
                fo.write(cipher.decrypt(chunk))
            fo.truncate(filesize)
