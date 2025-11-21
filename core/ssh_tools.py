from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
import os

def generate_ssh_key(key_type: str = 'rsa', save_dir: str = '.'):
    """Generates SSH keys and saves them to disk."""
    if key_type == 'rsa':
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_type == 'ed25519':
        key = ed25519.Ed25519PrivateKey.generate()
    elif key_type == 'ecdsa':
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError("Unsupported key type")

    # Private Key Serialization
    private_bytes = key.private_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=crypto_serialization.NoEncryption()
    )

    # Public Key Serialization
    public_key = key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=crypto_serialization.Encoding.OpenSSH,
        format=crypto_serialization.PublicFormat.OpenSSH
    )

    priv_path = os.path.join(save_dir, f"id_{key_type}")
    pub_path = os.path.join(save_dir, f"id_{key_type}.pub")

    with open(priv_path, 'wb') as f: f.write(private_bytes)
    with open(pub_path, 'wb') as f: f.write(public_bytes)

    return priv_path, pub_path, public_bytes.decode('utf-8')