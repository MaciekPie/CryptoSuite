import sys
from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QPushButton,
    QFileDialog,
    QLabel,
    QMessageBox,
    QHBoxLayout,
    QStackedWidget,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon
from crypto.rsa_cipher import generate_rsa_keypair
from crypto.hybrid import hybrid_encrypt_file, hybrid_decrypt_file


#  Main Application Window
# -------------------------
class MainApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptoSuite - Hybrid RSA + AES")
        self.resize(600, 400)

        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(30, 20, 30, 20)

        # Title
        title = QLabel("Hybrid RSA + AES Encryption Suite")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)

        # Description
        desc = QLabel("Easily encrypt and decrypt files using a hybrid AES + RSA method.")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)


        # Buttons section
        self.gen_keys_btn = QPushButton("Generate RSA keys")
        self.gen_keys_btn.clicked.connect(self.gen_keys)

        self.open_btn = QPushButton("Select file to encrypt")
        self.open_btn.clicked.connect(self.select_file_encrypt)

        self.select_pub_btn = QPushButton("Select public key (for encryption)")
        self.select_pub_btn.clicked.connect(self.select_pubkey)

        self.encrypt_btn = QPushButton("Encrypt file (Hybrid)")
        self.encrypt_btn.clicked.connect(self.encrypt_file)

        self.select_priv_btn = QPushButton("Select private key (for decryption)")
        self.select_priv_btn.clicked.connect(self.select_privkey)

        self.decrypt_btn = QPushButton("Decrypt file (Hybrid)")
        self.decrypt_btn.clicked.connect(self.decrypt_file)

        for btn in [
            self.gen_keys_btn,
            self.open_btn,
            self.select_pub_btn,
            self.encrypt_btn,
            self.select_priv_btn,
            self.decrypt_btn,
        ]:
            btn.setMinimumHeight(35)
            btn.setStyleSheet(
                """
                QPushButton {
                    background-color: #3498db;
                    color: white;
                    border-radius: 8px;
                    font-weight: 600;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
                """
            )
            layout.addWidget(btn)

        '''
        row1 = QHBoxLayout()
        self.gen_keys_btn = QPushButton("Generate RSA keys")
        self.gen_keys_btn.clicked.connect(self.gen_keys)
        row1.addWidget(self.gen_keys_btn)
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        self.open_btn = QPushButton("Select file to encrypt")
        self.open_btn.clicked.connect(self.select_file_encrypt)
        row2.addWidget(self.open_btn)
        layout.addLayout(row2)

        row3 = QHBoxLayout()
        self.select_pub_btn = QPushButton("Select public key (for encryption)")
        self.select_pub_btn.clicked.connect(self.select_pubkey)
        row3.addWidget(self.select_pub_btn)
        layout.addLayout(row3)

        row4 = QHBoxLayout()
        self.encrypt_btn = QPushButton("Encrypt (hybrid)")
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        row4.addWidget(self.encrypt_btn)
        layout.addLayout(row4)

        row5 = QHBoxLayout()
        self.select_priv_btn = QPushButton("Select private key (for decryption)")
        self.select_priv_btn.clicked.connect(self.select_privkey)
        row5.addWidget(self.select_priv_btn)
        layout.addLayout(row5)

        row6 = QHBoxLayout()
        self.decrypt_btn = QPushButton("Decrypt (hybrid)")
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        row6.addWidget(self.decrypt_btn)
        layout.addLayout(row6)
        '''

        self.status = QLabel("Ready")
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status)
        # layout.addWidget(self.status)

        self.setLayout(layout)

        # State
        self.infile = None
        # self.outfile = None
        self.pubkey = None
        self.privkey = None

    
    #  Functionality
    # ---------------

    def gen_keys(self):
        generate_rsa_keypair(outdir="keys/")
        QMessageBox.information(self, "Info", "Generated RSA keys in keys/")

    def select_file_encrypt(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Select file to encrypt")
        if fn:
            self.infile = fn
            self.status.setText(f"Selected file: {fn}")

    def select_pubkey(self):
        fn, _ = QFileDialog.getOpenFileName(
            self, "Select RSA public key", filter="PEM Files (*.pem)"
        )
        if fn:
            self.pubkey = fn
            self.status.setText(f"Selected public key: {fn}")

    def encrypt_file(self):
        if not self.infile or not self.pubkey:
            QMessageBox.warning(self, "Warning", "Select file and public key first")
            return

        outfile = hybrid_encrypt_file(self.infile, self.pubkey)
        QMessageBox.information(self, "Encryption complete", f"Encrypted file saved as:\n{outfile}")

    def select_privkey(self):
        fn, _ = QFileDialog.getOpenFileName(
            self, "Select RSA private key", filter="PEM Files (*.pem)"
        )
        if fn:
            self.privkey = fn
            self.status.setText(f"Selected private key: {fn}")

    def decrypt_file(self):
        fn, _ = QFileDialog.getOpenFileName(
            self, "Select file to decrypt", filter="All Files (*)"
        )
        if fn:
            if not self.privkey:
                QMessageBox.warning(self, "Warning", "Select private key first")
                return
            outfile = hybrid_decrypt_file(fn, self.privkey)
            QMessageBox.information(self, "Decryption complete", f"Decrypted file saved as:\n{outfile}")



#  Start Screen
# --------------
class StartScreen(QWidget):
    def __init__(self, switch_callback):
        super().__init__()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(15)

        title = QLabel("CryptoSuite")
        title.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel("Hybrid RSA + AES Encryption Tool")
        subtitle.setFont(QFont("Segoe UI", 14))
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        start_btn = QPushButton("Start Application")
        start_btn.setMinimumWidth(200)
        start_btn.setMinimumHeight(40)
        start_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border-radius: 10px;
                font-size: 16px;
                font-weight: bold;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
            """
        )
        start_btn.clicked.connect(switch_callback)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(start_btn)
        self.setLayout(layout)


#  App Controller
# ----------------
class CryptoApp(QStackedWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptoSuite")
        self.resize(650, 420)

        # Screens
        self.start_screen = StartScreen(self.show_main)
        self.main_app = MainApp()

        # Add to stack
        self.addWidget(self.start_screen)
        self.addWidget(self.main_app)

    def show_main(self):
        self.setCurrentWidget(self.main_app)


#  Run App
# ---------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = CryptoApp()
    w.show()
    sys.exit(app.exec())
