import base64
import binascii
import urllib.parse

def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def from_base64(data: str) -> bytes:
    try:
        return base64.b64decode(data)
    except binascii.Error:
        raise ValueError("Invalid Base64 string")

def to_hex(data: bytes) -> str:
    return data.hex()

def from_hex(data: str) -> bytes:
    try:
        return bytes.fromhex(data)
    except ValueError:
        raise ValueError("Invalid Hex string")

def url_encode(text: str) -> str:
    return urllib.parse.quote(text)

def url_decode(text: str) -> str:
    return urllib.parse.unquote(text)

def text_to_binary(text: str) -> str:
    """Visualizes text as a binary string."""
    return ' '.join(format(ord(char), '08b') for char in text)