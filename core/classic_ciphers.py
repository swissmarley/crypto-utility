def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
    """Shifts characters by a fixed amount."""
    if decrypt:
        shift = -shift
    
    result = []
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            # (Current Code - Start + Shift) % 26 + Start
            new_char = chr((ord(char) - start + shift) % 26 + start)
            result.append(new_char)
        else:
            result.append(char)
    return "".join(result)

def xor_cipher(text: str, key: int) -> str:
    """XORs every character with a specific integer key."""
    # Note: This is not one-time-pad; this is simple repeating XOR char
    return "".join(chr(ord(c) ^ key) for c in text)

def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> str:
    """Polyalphabetic substitution."""
    key = key.upper()
    result = []
    key_index = 0
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            if decrypt:
                shift = -shift
            
            start = ord('A') if char.isupper() else ord('a')
            new_char = chr((ord(char) - start + shift) % 26 + start)
            result.append(new_char)
            key_index += 1
        else:
            result.append(char)
            
    return "".join(result)