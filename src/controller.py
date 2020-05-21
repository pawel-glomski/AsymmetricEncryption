from crypto import *
from Crypto.PublicKey import RSA
from pathlib import Path


class Controller:
    def generate_keys(self, public_path, private_path, password):
        if password == '':
            password = None
        if public_path != '' and private_path != '':
            private_key = RSA.generate(2048)
            public_key = private_key.publickey()

            with open(public_path, 'wb') as f:
                f.write(public_key.export_key())

            with open(private_path, 'wb') as f:
                if password == None:
                    f.write(private_key.export_key())
                else:
                    f.write(private_key.export_key(passphrase=password))
            return True
        return False

    def load_public(self, public_path):
        self.public_key = None
        if public_path != '':
            with open(public_path, 'r') as f:
                self.public_key = RSA.import_key(f.read())
        return self.public_key

    def load_private(self, private_path, password):
        self.private_key = None
        if private_path != '':
            with open(private_path, 'r') as f:
                if password == None:
                    self.private_key = RSA.importKey(f.read())
                else:
                    self.private_key = RSA.importKey(
                        f.read(), passphrase=password)
        return self.private_key

    def encrypt(self, data_path, output_path):
        if output_path == '':
            return False
        if Path(output_path).suffix != '.encjson':
            output_path += '.encjson'
        public_key_string = self.public_key.export_key()
        encryptCTR(public_key_string, data_path, output_path)
        return True

    def decrypt(self, data_path, output_path):
        if output_path == '':
            return False
        decryptCTR(self.private_key.exportKey(), data_path, output_path)
        return True
