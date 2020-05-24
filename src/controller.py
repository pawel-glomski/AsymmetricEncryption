from Crypto.PublicKey import RSA
from pathlib import Path
import crypto


class Controller:
    """Class for manipulating keys and encrypting/decrypting files.

    :param private_key: Current private key.
    :type private_key: RSA private key (:class:`RSA.RsaKey`) or None
    :param public_key: Current public key.
    :type public_key: RSA public key (:class:`RSA.RsaKey`) or None
    """

    def generate_keys(self, public_path, private_path, password):
        """Generate private key and public key.

        This method generates both private and public keys and
        stores them as files and in appropriate fields.

        :param str public_path: Path to file for public key.
        :param str private_path: Path to file for private key.
        :param str password: Password for encrypting private key.
            If password is empty, then private key will not be encrypted.
        :return: True if neither public or private path were empty, False otherwise.
        :rtype: bool
        """
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
        """Load public key from file.

        :param str public_path: Path to file with public key.
        :return: Public key object if successfully loaded, None otherwise.
        :rtype: RSA public key (:class:`RSA.RsaKey`) or None
        """
        self.public_key = None
        if public_path != '':
            with open(public_path, 'r') as f:
                self.public_key = RSA.import_key(f.read())
        return self.public_key

    def load_private(self, private_path, password):
        """Load private key from file.

        :param str private_path: Path to file with private key.
        :param password: Password for decrypting private key.
        :type password: str or None
        :return: Private key object if successfully loaded, None otherwise.
        :rtype: RSA private key (:class:`RSA.RsaKey`) or None
        """
        self.private_key = None
        if private_path != '':
            with open(private_path, 'r') as f:
                if password == None:
                    self.private_key = RSA.importKey(f.read())
                else:
                    self.private_key = RSA.importKey(
                        f.read(), passphrase=password)
        return self.private_key

    def encrypt(self, encModeStr, data_path, output_path, progress):
        """Encrypt a file.

        :param str encModeStr: Chaining mode to use for encryption e.g. 'CBC'.
        :param str data_path: Path to file to encrypt.
        :param str output_path: Path to output file.
        :return: True if output_path isn't empty, False otherwise.
        :rtype: bool
        """
        if output_path == '':
            return False
        if Path(output_path).suffix != '.jsonenc':
            output_path += '.jsonenc'
        public_key_string = self.public_key.export_key()
        crypto.encrypt(encModeStr, public_key_string, data_path, output_path, progress)
        return True

    def decrypt(self, data_path, output_path, progress):
        """Decrypt a file.

        :param str data_path: Path to file to decrypt.
        :param str output_path: Path to output file.
        :return: True if output_path isn't empty, False otherwise.
        :rtype: bool
        """
        if output_path == '':
            return False
        crypto.decrypt(self.private_key.exportKey(), data_path, output_path, progress)
        return True
