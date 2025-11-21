import os

# Base Output Directory
OUTPUT_DIR = "output"

def ensure_output_dir():
    """Creates the main output directory if it doesn't exist."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    return OUTPUT_DIR

def get_path(filename: str, subdir: str = None) -> str:
    """
    Constructs a path.
    If 'filename' is absolute, returns it.
    Otherwise, places it in output/subdir/filename.
    """
    # If user provides a full path (e.g. /tmp/file), respect it.
    if os.path.isabs(filename) or os.path.dirname(filename):
        return filename

    # Determine target directory
    if subdir:
        target_dir = os.path.join(OUTPUT_DIR, subdir)
    else:
        target_dir = OUTPUT_DIR

    # Create directory if missing
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    return os.path.join(target_dir, filename)

def read_file_bytes(filepath: str) -> bytes:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    with open(filepath, 'rb') as f:
        return f.read()

def write_file_bytes(filename: str, data: bytes, subdir: str = None, mode='wb') -> str:
    """Writes data to output/subdir/filename."""
    full_path = get_path(filename, subdir)
    
    # Ensure the folder exists (redundant check for safety)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    
    with open(full_path, mode) as f:
        f.write(data)
    return full_path