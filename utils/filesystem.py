import os

def ensure_dirs(*dirs):
    """Creates directories if they do not exist."""
    for directory in dirs:
        os.makedirs(directory, exist_ok=True)

def list_files(directory, ext=None):
    """Returns sorted files from directory."""
    try:
        files = os.listdir(directory)

        if ext:
            files = [f for f in files if f.endswith(ext)]

        return sorted(files)

    except FileNotFoundError:
        return []