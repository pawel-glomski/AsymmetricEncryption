import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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
                chunk  = fi.read(chunkSize)
                if len(chunk) == 0:
                    break
                elif len(chunk)%16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))
                fo.write(encryptor.encrypt(chunk))

def AESdecryptCBC(key, filename, outputFilename, chunkSize=64*1024):
    with open(filename, 'rb') as fi:
        _, filesize, IV = loadHeader(fi)
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        with open(outputFilename, 'wb') as fo:
            while True:
                chunk  = fi.read(chunkSize)
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
