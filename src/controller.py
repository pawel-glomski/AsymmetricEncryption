from crypto import *
from Crypto.PublicKey import RSA


class Controller:
    def generate_keys(self, public_path, private_path, password):
        if password == '':
            password = None
        if public_path != '' and private_path != '':
            generate_keys(public_path, private_path, password)
        else:
            return
        self.load_keys(public_path, private_path, password)

    def load_keys(self, public_path, private_path, password):
        (self.public_key, self.private_key) = load_keys(public_path, private_path, password)

    def encrypt(self, data_path, output_path):
        with open(data_path, 'rb') as f:
            data = f.read()
        public_key_string = self.public_key.export_key()
        result = encrypt(public_key_string, data)
        print(result)
