from PyQt5 import uic
from PyQt5.QtWidgets import *
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
        self.outputPath = self.findChild(QLineEdit, 'outputPath')
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

    def chooseInputFile(self):
        self.inputPath.setText(QFileDialog.getOpenFileName()[0])

    def choosePrivateKeyFile(self):
        self.privatePath.setText(QFileDialog.getOpenFileName()[0])

    def choosePublicKeyFile(self):
        self.publicPath.setText(QFileDialog.getOpenFileName()[0])

    def genKeys(self):
        self.controller.generate_keys(self.publicPath.text(
        ), self.privatePath.text(), self.password.text())

    def encrypt(self):
        self.controller.load_keys(self.publicPath.text(
        ), self.privatePath.text(), self.password.text())
        self.controller.encrypt(self.inputPath.text(), self.outputPath.text())

    def decrypt(self):
        self.controller.load_keys(self.publicPath.text(
        ), self.privatePath.text(), self.password.text())
        self.controller.decrypt(self.inputPath.text(), self.outputPath.text())


app = QApplication([])
window = UiWindow()
app.exec_()
