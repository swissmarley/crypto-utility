import hashlib

def hash_data(data: bytes, algo: str = 'sha256') -> str:
    if algo not in hashlib.algorithms_available:
        raise ValueError(f"Algorithm {algo} not supported.")
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()

def hash_file(filepath: str, algo: str = 'sha256') -> str:
    h = hashlib.new(algo)
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()