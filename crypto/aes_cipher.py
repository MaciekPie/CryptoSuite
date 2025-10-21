# AES symmetric encryption using AES-GCM (authenticated)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def aes_encrypt(data: bytes, key: bytes):
    # key: bytes (16, 24, 32 bytes for AES-128/192/256)
    iv = get_random_bytes(12)  # recommended for GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
        'iv': iv,
        'ciphertext': ciphertext,
        'tag': tag,
    }

def aes_decrypt(enc_dict: dict, key: bytes):
    iv = enc_dict['iv']
    ciphertext = enc_dict['ciphertext']
    tag = enc_dict['tag']
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
