import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def generate_fernet_key():
    return Fernet.generate_key()

def fernet_encrypt(key: bytes, data: bytes) -> bytes:
    return Fernet(key).encrypt(data)

def fernet_decrypt(key: bytes, data: bytes) -> bytes:
    return Fernet(key).decrypt(data)

def aes_gcm_encrypt(key: bytes, plaintext: bytes):
    """Encrypts using AES-256-GCM."""
    # Generate a random 96-bit IV (12 bytes)
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # Return IV + Tag + Ciphertext for portability
    return iv + encryptor.tag + ciphertext

def aes_gcm_decrypt(key: bytes, data: bytes):
    """Decrypts AES-256-GCM (Expects IV(12) + Tag(16) + Ciphertext)."""
    iv = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()