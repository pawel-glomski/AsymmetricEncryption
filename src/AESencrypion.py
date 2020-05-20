import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def AESencryptCBC(key, filename, outputFilename, chunkSize=64*1024):
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = get_random_bytes(16)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    
    with open(filename, 'rb') as fi:
        with open(outputFilename, 'wb') as fo:
            mode = 'CBC'
            fo.write(str(len(mode)).zfill(16).encode('utf-8'))
            fo.write(mode.zfill(16).encode('utf-8'))
            fo.write(filesize.encode('utf-8'))
            fo.write(IV)
            while True:
                chunk  = fi.read(chunkSize)
                if len(chunk) == 0:
                    break
                elif len(chunk)%16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))
                fo.write(encryptor.encrypt(chunk))

def AESdecryptCBC(key, filename, outputFilename, chunkSize=64*1024):
    with open(filename, 'rb') as fi:
        modeLength = int(fi.read(16))
        mode = fi.read(16).decode('utf-8')
        filesize = int(fi.read(16))
        IV = fi.read(16)
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
        modeLength = int(fi.read(16))
        mode = fi.read(16).decode('utf-8')
    if mode[-modeLength:] == 'CBC':
        AESdecryptCBC(key, filename, outputFilename, chunkSize=64*1024)
    else:
        print('Unknown mode: '+mode)
