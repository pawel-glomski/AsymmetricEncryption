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
        (self.public_key, self.private_key) = load_keys(
            public_path, private_path, password)

    def encrypt(self, data_path, output_path):
        with open(data_path, 'rb') as f:
            data = f.read()
        public_key_string = self.public_key.export_key()
        result = encrypt(public_key_string, data)
        output_path += '.json'
        with open(output_path, 'w') as f:
            json.dump(result, f)

    def decrypt(self, data_path, output_path):
        with open(data_path, 'r') as f:
            json_data = json.load(f)
        decrypted_data = decrypt(self.private_key.exportKey(), json_data)
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
