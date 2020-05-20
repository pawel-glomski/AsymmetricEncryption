from PyQt5 import uic
from PyQt5.QtWidgets import *
from Crypto.PublicKey import RSA, DSA
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

import crypto
from controller import *


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

        self.controller = Controller()

    def showPopup(self, text, icon=QMessageBox.Critical):
        msg = QMessageBox()
        msg.setIcon(icon)
        msg.setText(text)
        msg.exec()

    def chooseInputFile(self):
        self.inputPath.setText(QFileDialog.getOpenFileName()[0])

    def choosePrivateKeyFile(self):
        self.privatePath.setText(QFileDialog.getOpenFileName()[0])

    def choosePublicKeyFile(self):
        self.publicPath.setText(QFileDialog.getOpenFileName()[0])

    def genKeys(self):
        if self.controller.generate_keys(self.publicPath.text(), self.privatePath.text(), self.password.text()):
            self.showPopup('Wygenerowano pomyślnie', QMessageBox.Information)
        else:
            self.showPopup('Podaj poprawne ścieżki do zapisu wygenerowanych kluczy')

    def encrypt(self):
        if self.controller.load_public(self.publicPath.text()) is None:
            return self.showPopup('Zła ścieżka pliku z kluczem')

        inputPath = Path(self.inputPath.text())
        if inputPath.is_file():
            if self.controller.encrypt(self.inputPath.text(), QFileDialog.getSaveFileName(self, 'Zapisz zaszyfrowany plik')[0]):
                self.showPopup('Zaszyfrowano pomyślnie', QMessageBox.Information)
        else:
            self.showPopup('Zła ścieżka pliku do szyfrowania')

    def decrypt(self):
        try:
            if self.controller.load_private(self.privatePath.text(), self.password.text()) is None:
                return self.showPopup('Zła ścieżka pliku z kluczem')
        except:
            return self.showPopup('Błąd odczytu klucza')

        inputPath = Path(self.inputPath.text())
        if inputPath.is_file():
            try:
                if self.controller.decrypt(self.inputPath.text(), QFileDialog.getSaveFileName(self, 'Zapisz odszyfrowany plik')[0]):
                    self.showPopup('Odszyfrowano pomyślnie', QMessageBox.Information)
            except:
                return self.showPopup('Błędny format pliku')
        else:
            self.showPopup('Zła ścieżka pliku do odszyfrowania')

    # def encrypt(self):
    #     print("Szyfrowanie pliku:", self.inputPath.text(), "trybem: ", self.encModeBox.currentText())
    #     saveFile = QFileDialog.getSaveFileName(self, 'Zapisz zaszyfrowany plik')[0]
    #     if self.encModeBox.currentText() == 'CBC':
    #         hashedPassword = SHA256.new(self.password.text().encode('utf-8')).digest()
    #         AESencryptCBC(hashedPassword, self.inputPath.text(), saveFile)
    #     else:
    #         print('Not implemented')

    # def decrypt(self):
    #     saveFile = QFileDialog.getSaveFileName(self, 'Zapisz odszyfrowany plik')[0]
    #     hashedPassword = SHA256.new(self.password.text().encode('utf-8')).digest()
    #     AESdecrypt(hashedPassword, self.inputPath.text(), saveFile)


app = QApplication([])
window = UiWindow()
app.exec_()
