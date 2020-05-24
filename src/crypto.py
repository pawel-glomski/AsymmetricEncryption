from pathlib import Path
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from math import ceil
import os
import mmap
import json

EncryptedDataLabel = b'encrypted_file:'


def makeCipher(encModeStr: str, sym_key: bytes, filesize: int, initBytes=None):
    """Create an AES cipher of a desired mode.

    :param str encModeStr: Chaining mode to use for encryption or decryption e.g. 'CBC'.
    :param bytes sym_key: The secret key to use in the symmetric cipher.
    :param int filesize: Size of a file to encrypt or decrypt.
    :param initBytes: Initial bytes to be used as either initialization vector
        or nonce (default None).
    :type initBytes: bytes, bytearray, memoryview or None
    :return: an AES object.
    """
    mode = getattr(AES, 'MODE_'+encModeStr)
    if mode == AES.MODE_CCM:
        filesize += 100
        return AES.new(sym_key, mode, nonce=initBytes, msg_len=filesize)
    if initBytes is None:
        return AES.new(sym_key, mode)
    if hasattr(AES.new(sym_key, mode), 'nonce'):
        return AES.new(sym_key, mode, nonce=initBytes)
    return AES.new(sym_key, mode, initBytes)  # iv


def makeHeader(cipher, sym_key: bytes, encModeStr: str, public_key_string: str,
               filesize: int) -> str:
    """Create a json formatted header.

    :param cipher: AES cipher object.
    :param bytes sym_key: The secret key used in the cipher.
    :param str encModeStr: Chaining mode used in cipher e.g. 'CBC'.
    :param str public_key_string: Public key to use for encrypting sym_key.
    :param int filesize: Size of a file to encrypt.
    :return: json formatted header
    :rtype: str
    """
    initBytes = cipher.nonce if hasattr(cipher, 'nonce') else cipher.iv
    encrypted_key = PKCS1_OAEP.new(
        RSA.import_key(public_key_string)).encrypt(sym_key)
    return json.dumps({'initBytes': b64encode(initBytes).decode('utf-8'),
                       'encrypted_key': b64encode(encrypted_key).decode('utf-8'),
                       'mode': encModeStr,
                       'filesize': filesize})


def encrypt(encModeStr, public_key_string, data_path, ouput_path, progress, chunkSize=64*1024):
    """Encrypt a file.

    :param str encModeStr: Chaining mode to use for encryption e.g. 'CBC'.
    :param str public_key_string: Public key to use for encrypting symmetric key.
    :param str data_path: Path to file to encrypt.
    :param str output_path: Path to output file.
    :param int chunkSize: Size of chunks of a file encrypted at one
        moment. The greater this value, the greater memory consumption (default 65536).
    """
    sym_key = get_random_bytes(32)
    filesize = os.path.getsize(data_path)
    cipher = makeCipher(encModeStr, sym_key, filesize)
    json_header = makeHeader(cipher, sym_key, encModeStr,
                             public_key_string, filesize)
    encryptToFile(data_path, json_header, ouput_path, cipher, chunkSize, progress)


def encryptToFile(data_path, header, output_path, cipher, chunkSize, progress):
    """Encrypt a file.

    :param str data_path: Path to file to encrypt.
    :param str header: json formatted string with header for encrypted file.
    :param str output_path: Path to output file.
    :param cipher: AES cipher object for encrypting data.
    :param int chunkSize: Size of chunks of a file encrypted at one
        moment. The greater this value, the greater memory consumption.
    """
    with open(output_path, 'w') as fo:
        fo.write(header)
        fo.write(EncryptedDataLabel.decode('ascii'))

    iters = ceil(Path(data_path).stat().st_size / chunkSize)
    i = 0

    with open(data_path, 'rb') as fi:
        with open(output_path, 'ab') as fo:
            while True:
                progress.setValue(i/iters*100)
                i += 1

                chunk = fi.read(chunkSize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))
                fo.write(cipher.encrypt(chunk))


def decrypt(private_key_string, data_path, ouput_path, progress, chunkSize=64*1024):
    """Decrypt a file.

    :param str private_key_string: Private key to use for decrypting symmetric key.
    :param str data_path: Path to file to decrypt.
    :param str output_path: Path to output file.
    :param int chunkSize: Size of chunks of a file encrypted at one
        moment. The greater this value, the greater memory consumption (default 65536).
    """
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
                  data_offset, filesize, chunkSize, progress)


def decryptToFile(data_path, output_path, cipher, data_offset, filesize, chunkSize, progress):
    """Decrypt a file.

    :param str data_path: Path to file to decrypt.
    :param str output_path: Path to output file.
    :param cipher: AES cipher object for decrypting data.
    :param int data_offset: Position of begining of encrypted data in file.
    :param int filesize: Desired size of output file, read from the file header.
    :param int chunkSize: Size of chunks of a file encrypted at one
        moment. The greater this value, the greater memory consumption.
    """
    iters = ceil(filesize / chunkSize)
    i = 0
    with open(data_path, 'rb') as fi:
        fi.seek(data_offset)
        with open(output_path, 'wb') as fo:
            while True:
                progress.setValue(i/iters*100)
                i += 1

                chunk = fi.read(chunkSize)
                if len(chunk) == 0:
                    break
                fo.write(cipher.decrypt(chunk))
            fo.truncate(filesize)
