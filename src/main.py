from PyQt5 import uic
from PyQt5.QtWidgets import *
from Crypto.PublicKey import RSA, DSA
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from pathlib import Path

import crypto
from AESencrypion import AESencryptCBC, AESdecrypt


class UiWindow(QMainWindow):
    def __init__(self):
        super(UiWindow, self).__init__()
        uic.loadUi('interface.ui', self)
        self.fileButton = self.findChild(QToolButton, 'fileButton')
        self.privateButton = self.findChild(QToolButton, 'privateButton')
        self.publicButton = self.findChild(QToolButton, 'publicButton')
        self.encryptButton = self.findChild(QPushButton, 'encryptButton')
        self.decryptButton = self.findChild(QPushButton, 'decryptButton')
        self.genButton = self.findChild(QPushButton, 'genButton')

        self.inputPath = self.findChild(QLineEdit, 'inputPath')
        self.privatePath = self.findChild(QLineEdit, 'privatePath')
        self.publicPath = self.findChild(QLineEdit, 'publicPath')

        self.encModeBox = self.findChild(QComboBox, 'encModeBox')
        self.password = self.findChild(QLineEdit, 'password')

        self.fileButton.clicked.connect(self.chooseInputFile)
        self.privateButton.clicked.connect(self.choosePrivateKeyFile)
        self.publicButton.clicked.connect(self.choosePublicKeyFile)
        self.encryptButton.clicked.connect(self.encrypt)
        self.decryptButton.clicked.connect(self.decrypt)
        self.genButton.clicked.connect(self.genKeys)

        self.show()

    def chooseInputFile(self):
        self.inputPath.setText(QFileDialog.getOpenFileName()[0])

    def choosePrivateKeyFile(self):
        self.privatePath.setText(QFileDialog.getOpenFileName()[0])

    def choosePublicKeyFile(self):
        self.publicPath.setText(QFileDialog.getOpenFileName()[0])

    def genKeys(self):
        print('genKeys')
        ...  # save at privatePath and publicPath

    def showPopup(self, text, icon=QMessageBox.Critical):
        msg = QMessageBox()
        msg.setIcon(icon)
        msg.setText(text)
        msg.exec()

    def encrypt(self):
        inputPath = Path(self.inputPath.text())
        keyPath = Path(self.publicPath.text())
        if inputPath.is_file() and keyPath.is_file():
            with open(inputPath, 'rb') as f:
                buffer = f.read()
            with open(keyPath, 'rb') as key:
                try:
                    jsonData = crypto.encryptCTR(key.read(), buffer)
                except ValueError:
                    return self.showPopup('Zły plik z kluczem')
            with open(QFileDialog.getSaveFileName(self, 'Zapisz zaszyfrowany plik')[0], 'w') as jsonFile:
                jsonFile.write(jsonData)
        else:
            self.showPopup(('Zła ścieżka pliku do szyfrowania' if not inputPath.is_file() else '') +
                           '\nZła ścieżka pliku z kluczem' if not keyPath.is_file() else '')

    def decrypt(self):
        inputPath = Path(self.inputPath.text())
        keyPath = Path(self.privatePath.text())
        if inputPath.is_file() and keyPath.is_file():
            with open(inputPath, 'rb') as f:
                buffer = f.read()
            with open(keyPath, 'rb') as key:
                try:
                    data = crypto.decryptCTR(key.read(), buffer)
                except ValueError:
                    return self.showPopup('Zły plik z kluczem')
            with open(QFileDialog.getSaveFileName(self, 'Zapisz odszyfrowany plik')[0], 'w') as f:
                f.write(data)

        else:
            self.showPopup(('Zła ścieżka pliku do odszyfrowania' if not inputPath.is_file() else '') +
                           '\nZła ścieżka pliku z kluczem' if not keyPath.is_file() else '')

        print("Szyfrowanie pliku:", self.inputPath.text(), "trybem: ", self.encModeBox.currentText())
        saveFile = QFileDialog.getSaveFileName(self, 'Zapisz zaszyfrowany plik')[0]
        if self.encModeBox.currentText() == 'CBC':
            hashedPassword = SHA256.new(self.password.text().encode('utf-8')).digest()
            AESencryptCBC(hashedPassword, self.inputPath.text(), saveFile)
        else:
            print('Not implemented')

    def decrypt(self):
        saveFile = QFileDialog.getSaveFileName(self, 'Zapisz odszyfrowany plik')[0]
        hashedPassword = SHA256.new(self.password.text().encode('utf-8')).digest()
        AESdecrypt(hashedPassword, self.inputPath.text(), saveFile)


app = QApplication([])
window = UiWindow()
app.exec_()
