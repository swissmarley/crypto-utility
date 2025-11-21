from cryptography.hazmat.primitives import serialization

def pem_to_der(pem_data: bytes) -> bytes:
    """Detects if public or private key and converts PEM to DER."""
    # Try loading as private key
    try:
        key = serialization.load_pem_private_key(pem_data, password=None)
        return key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    except Exception:
        pass

    # Try loading as public key
    try:
        key = serialization.load_pem_public_key(pem_data)
        return key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception:
        raise ValueError("Could not parse PEM data (or password required)")

def der_to_pem(der_data: bytes, is_private: bool = False) -> bytes:
    """Converts DER to PEM."""
    if is_private:
        key = serialization.load_der_private_key(der_data, password=None)
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        key = serialization.load_der_public_key(der_data)
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )