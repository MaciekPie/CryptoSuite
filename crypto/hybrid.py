# Hybrid RSA + AES: encrypt file with AES-GCM and encrypt AES key with RSA-OAEP.
import json, base64, os
from Crypto.Random import get_random_bytes
from .aes_cipher import aes_encrypt, aes_decrypt
from .rsa_cipher import rsa_encrypt, rsa_decrypt

def _b64(x: bytes) -> str:
    return base64.b64encode(x).decode('ascii')

def _ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))

# =============== Core hybrid logic ===============

def hybrid_encrypt_bytes(plaintext: bytes, pubkey_path: str):
    # generate AES key
    aes_key = get_random_bytes(32)  # AES-256
    # encrypt data symmetrically
    enc = aes_encrypt(plaintext, aes_key)
    # encrypt AES key with RSA public key

    with open(pubkey_path, 'rb') as f:
        pub = f.read()

    enc_key = rsa_encrypt(aes_key, pub)
    # prepare package
    package = {
        'aes_key_encrypted': _b64(enc_key),
        'aes': {
            'iv': _b64(enc['iv']),
            'ciphertext': _b64(enc['ciphertext']),
            'tag': _b64(enc['tag']),
        }
    }
    return json.dumps(package).encode('utf-8')


def hybrid_decrypt_bytes(package_bytes: bytes, privkey_path: str):
    with open(privkey_path, 'rb') as f:
        priv = f.read()

    package = json.loads(package_bytes.decode('utf-8'))
    enc_key = _ub64(package['aes_key_encrypted'])
    aes_key = rsa_decrypt(enc_key, priv)

    a = package['aes']
    enc_dict = {
        'iv': _ub64(a['iv']),
        'ciphertext': _ub64(a['ciphertext']),
        'tag': _ub64(a['tag']),
    }
    plaintext = aes_decrypt(enc_dict, aes_key)
    return plaintext


# =============== File handling ===============


def _build_output_path(infile: str, decrypt: bool = False) -> str:
    """
    Tworzy logiczną nazwę pliku wynikowego.
    Jeśli decrypt=True → usuwa _encrypted i dodaje _decrypted.
    """
    base, ext = os.path.splitext(infile)

    if not decrypt:
        # Encrypt
        return f"{base}_encrypted.bin"
    else:
        # Decrypt
        # Jeśli plik był np. file_encrypted.bin → zrób file_decrypted.txt
        if base.endswith("_encrypted"):
            base = base.replace("_encrypted", "")
        return f"{base}_decrypted{ext or '.txt'}"


def hybrid_encrypt_file(infile: str, pubkey_path: str):
    with open(infile, 'rb') as f:
        data = f.read()

    pkg = hybrid_encrypt_bytes(data, pubkey_path)
    outfile = _build_output_path(infile, decrypt=False)

    with open(outfile, 'wb') as f:
        f.write(pkg)

    print(f"Zapisano zaszyfrowany plik: {outfile}")
    return outfile


def hybrid_decrypt_file(infile: str, privkey_path: str):
    with open(infile, 'rb') as f:
        pkg = f.read()

    plaintext = hybrid_decrypt_bytes(pkg, privkey_path)
    outfile = _build_output_path(infile, decrypt=True)

    with open(outfile, 'wb') as f:
        f.write(plaintext)

    print(f"[✔] Odszyfrowano do pliku: {outfile}")
    return outfile
