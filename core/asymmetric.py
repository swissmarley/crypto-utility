import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_rsa_pair(key_size=2048):
    """Generates a private/public RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_private_key(private_key, password: str = None) -> bytes:
    """Converts private key object to PEM bytes."""
    encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )

def serialize_public_key(public_key) -> bytes:
    """Converts public key object to PEM bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def rsa_encrypt(public_key_pem: bytes, message: bytes) -> bytes:
    """Encrypts data using RSA-OAEP."""
    public_key = serialization.load_pem_public_key(public_key_pem)
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(private_key_pem: bytes, ciphertext: bytes, password: str = None) -> bytes:
    """Decrypts data using RSA-OAEP."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None if not password else password.encode())
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def rsa_sign(private_key_pem: bytes, data: bytes) -> bytes:
    """Signs data using RSA-PSS."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def rsa_verify(public_key_pem: bytes, signature: bytes, data: bytes) -> bool:
    """Verifies a signature using RSA-PSS."""
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False