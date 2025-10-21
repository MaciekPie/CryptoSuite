# CryptoSuite (hybrid RSA + AES)

Projekt: hybrydowy system szyfrowania (RSA + AES) — Python + PySide6.

**Wymagania**
- Python 3.8+
- PySide6 (GUI)  -> `pip install PySide6`
- PyCryptodome (kryptografia) -> `pip install pycryptodome`

**Zawartość**
- `main.py` — prosty CLI / punkt wejścia
- `gui/app.py` — szkic GUI w PySide6
- `crypto/aes_cipher.py` — AES-GCM (szyfrowanie symetryczne)
- `crypto/rsa_cipher.py` — RSA generacja kluczy + OAEP (asymetryczne)
- `crypto/hybrid.py` — łączenie RSA + AES (hybrydowe szyfrowanie)
- `utils/file_manager.py` — pomoc dla plików (zapis/odczyt binarny + JSON wrapper)
- `keys/` — katalog docelowy na klucze RSA
- `examples/` — przykładowe zaszyfrowane pliki (puste)

**Uruchomienie**
- Wygeneruj klucze RSA (używając modułu `crypto.rsa_cipher` lub GUI).
- Uruchom `python main.py --help` aby zobaczyć opcje CLI.

To jest szkic startowy — mogę teraz rozwinąć każdy moduł, dodać testy i GUI funkcjonalne.
