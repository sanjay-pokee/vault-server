
import json
import threading
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_FILE = DATA_DIR / "audit_log.json"

# Thread lock to prevent concurrent writes/reads from corrupting the log file
_log_lock = threading.Lock()

def _ensure_log_file():
    if not LOG_FILE.exists():
        with open(LOG_FILE, "w") as f:
            json.dump([], f)

def log_action(username: str, action: str, details: str = None):
    _ensure_log_file()
    
    timestamp = datetime.now().isoformat()
    entry = {
        "timestamp": timestamp,
        "username": username,
        "action": action,
        "details": details or ""
    }
    
    try:
        with _log_lock:
            with open(LOG_FILE, "r+") as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []
                    
                logs.append(entry)
                f.seek(0)
                json.dump(logs, f, indent=2)
                f.truncate()
    except Exception as e:
        print(f"Error writing audit log: {e}")

def get_logs(username: str):
    _ensure_log_file()
    
    try:
        with _log_lock:
            with open(LOG_FILE, "r") as f:
                all_logs = json.load(f)
            
        # Filter logs for the specific user
        user_logs = [log for log in all_logs if log["username"] == username]
        
        # Sort by timestamp descending
        user_logs.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return user_logs
    except Exception as e:
        print(f"Error reading audit log: {e}")
        return []
