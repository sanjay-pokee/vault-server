import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

def _path(username):
    return DATA_DIR / f"{username}.json"

def store_blob(username, blob):
    with open(_path(username), "w") as f:
        json.dump(blob, f)

def load_blob(username):
    path = _path(username)
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError:
        return None
