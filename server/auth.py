import json
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
AUTH_DB = BASE_DIR / "auth_db.json"

if not AUTH_DB.exists():
    AUTH_DB.write_text("{}")

SESSIONS = {}

def _load():
    text = AUTH_DB.read_text().strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}

def _save(data):
    AUTH_DB.write_text(json.dumps(data))

def register_user(username: str, salt: str, verifier: str):
    users = _load()
    if username in users:
        raise ValueError("User exists")
    users[username] = {
        "salt": salt,
        "verifier": verifier,
    }
    _save(users)

def get_auth_salt(username: str):
    users = _load()
    return users.get(username, {}).get("salt")

def login_user(username: str, verifier: str):
    users = _load()
    user = users.get(username)
    if not user or user["verifier"] != verifier:
        raise ValueError("Invalid credentials")

    token = secrets.token_hex(32)
    SESSIONS[token] = username
    return token

def require_auth(token: str):
    if token not in SESSIONS:
        raise ValueError("Unauthorized")
    return SESSIONS[token]
