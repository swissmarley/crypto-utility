import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
from utils.file_utils import get_path

# Automatically places the vault in the output folder
VAULT_FILE = get_path("my_secrets.vault", subdir="vault")

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def init_vault(password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    empty_vault = json.dumps({})
    encrypted_data = f.encrypt(empty_vault.encode())
    
    # writes to output/my_secrets.vault via get_path defined in global constant
    with open(VAULT_FILE, 'wb') as file:
        file.write(salt + encrypted_data)
    return "Vault initialized."

def get_secret(password: str, key_name: str):
    if not os.path.exists(VAULT_FILE): return "Vault not found."
    with open(VAULT_FILE, 'rb') as file:
        data = file.read()
    
    salt, ciphertext = data[:16], data[16:]
    key = derive_key(password, salt)
    f = Fernet(key)
    
    try:
        decrypted_data = f.decrypt(ciphertext)
        vault = json.loads(decrypted_data)
        return vault.get(key_name, "Secret not found.")
    except Exception:
        return "Invalid Password or Corrupt Vault."

def add_secret(password: str, key_name: str, value: str):
    if not os.path.exists(VAULT_FILE): init_vault(password)
    
    with open(VAULT_FILE, 'rb') as file: data = file.read()
    salt, ciphertext = data[:16], data[16:]
    key = derive_key(password, salt)
    f = Fernet(key)
    
    try:
        decrypted_data = f.decrypt(ciphertext)
        vault = json.loads(decrypted_data)
        vault[key_name] = value
        
        new_ciphertext = f.encrypt(json.dumps(vault).encode())
        with open(VAULT_FILE, 'wb') as file:
            file.write(salt + new_ciphertext)
        return "Secret stored."
    except Exception:
        return "Authentication failed."