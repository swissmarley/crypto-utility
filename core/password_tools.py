import secrets
import string
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

def hash_password(password: str) -> str:
    """Hashes a password using Argon2id."""
    return ph.hash(password)

def verify_password(hash_str: str, password: str) -> bool:
    """Verifies a password against an Argon2id hash."""
    try:
        ph.verify(hash_str, password)
        return True
    except VerifyMismatchError:
        return False

def generate_password(length: int = 16, special_chars: bool = True) -> str:
    """Generates a cryptographically secure random password."""
    alphabet = string.ascii_letters + string.digits
    if special_chars:
        alphabet += string.punctuation
    
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Ensure at least one of each type if special chars are requested
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)):
            if special_chars and any(c in string.punctuation for c in password):
                return password
            elif not special_chars:
                return password

def check_strength(password: str) -> dict:
    """Basic heuristic strength check."""
    length_score = len(password) >= 12
    complexity_score = (
        any(c.isupper() for c in password) and 
        any(c.islower() for c in password) and 
        any(c.isdigit() for c in password) and 
        any(c in string.punctuation for c in password)
    )
    
    if length_score and complexity_score:
        return {"strength": "Strong", "color": "green"}
    elif length_score or complexity_score:
        return {"strength": "Medium", "color": "yellow"}
    return {"strength": "Weak", "color": "red"}