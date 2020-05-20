
from PyQt5 import uic
from PyQt5.QtWidgets import *


class UiWindow(QMainWindow):
    def __init__(self):
        super(UiWindow, self).__init__()
        uic.loadUi('dialog.ui', self)

        self.fileButton = self.findChild(QToolButton, 'fileButton')
        self.inputPath = self.findChild(QLineEdit, 'inputPath')
        self.outputPath = self.findChild(QLineEdit, 'outputPath')
        self.encryptButton = self.findChild(QPushButton, 'encryptButton')
        self.algorithmsBox = self.findChild(QComboBox, 'algorithmsBox')

        self.fileButton.clicked.connect(self.chooseInputFile)
        self.encryptButton.clicked.connect(self.encrypt)

        self.show()

    def chooseInputFile(self):
        self.inputPath.setText(QFileDialog.getOpenFileName()[0])

    def encrypt(self):
        print("Szyfrowanie pliku:", self.inputPath.text(), "do:", self.outputPath.text(), "algorytmem: ", self.algorithmsBox.currentText())


app = QApplication([])
window = UiWindow()
app.exec_()
