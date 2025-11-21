import os
import re

def validate_file_exists(filepath: str) -> bool:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    return True

def validate_hex(value: str) -> bool:
    """Checks if string is valid hex."""
    try:
        int(value, 16)
        return True
    except ValueError:
        return False

def validate_base64(value: str) -> bool:
    """Checks if string looks like base64."""
    # Simple regex check
    pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    return bool(pattern.fullmatch(value)) and (len(value) % 4 == 0)