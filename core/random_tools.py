import secrets
import uuid
import string

def generate_token_hex(nbytes: int = 32) -> str:
    return secrets.token_hex(nbytes)

def generate_token_urlsafe(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)

def generate_uuid() -> str:
    return str(uuid.uuid4())

def generate_pin(length: int = 6) -> str:
    return ''.join(secrets.choice(string.digits) for _ in range(length))