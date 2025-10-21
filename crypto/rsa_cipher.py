# RSA key generation and RSA-OAEP encryption/decryption for small blobs (e.g. AES key)
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os

def generate_rsa_keypair(bits: int = 2048, outdir: str = 'keys/'):
    os.makedirs(outdir, exist_ok=True)
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open(os.path.join(outdir, 'private.pem'), 'wb') as f:
        f.write(private_key)
    with open(os.path.join(outdir, 'public.pem'), 'wb') as f:
        f.write(public_key)
    print(f'Wygenerowano klucze w {outdir} (private.pem, public.pem)')

def rsa_encrypt(data: bytes, pubkey_pem: bytes):
    rsa_key = RSA.import_key(pubkey_pem)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(data)

def rsa_decrypt(enc: bytes, privkey_pem: bytes):
    rsa_key = RSA.import_key(privkey_pem)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(enc)
