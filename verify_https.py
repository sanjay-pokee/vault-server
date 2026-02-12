"""
TESTS USER STORY: 5.2 (HTTPS/TLS)
Goal: Verify that the server accepts secure HTTPS connections.
"""
import requests
import urllib3
import json
from pathlib import Path

# Disable warning about self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_PATH = Path(__file__).parent / "tests" / "data" / "https_config.jsonc"

def verify_https():
    if not CONFIG_PATH.exists():
        print(f"Error: Config file not found at {CONFIG_PATH}")
        return

    try:
        # Load config with comment support
        # We need to add tests dir to path if running from root
        import sys
        sys.path.append(str(Path(__file__).parent))
        from tests.json_utils import load_json_with_comments
        
        config = load_json_with_comments(CONFIG_PATH)
            
        url = config.get("url", "https://127.0.0.1:8000")
        timeout = config.get("timeout", 5)
        verify = config.get("verify_cert", False)
        expected = config.get("expected_statuses", [200])
        
        print(f"Testing HTTPS connection to {url}...")
        
        response = requests.get(url, verify=verify, timeout=timeout)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code in expected:
            print("SUCCESS: HTTPS connection established.")
        else:
            print(f"Unexpected status: {response.status_code}")
            
    except Exception as e:
        print(f"FAILURE: Could not connect to HTTPS server. Error: {e}")

if __name__ == "__main__":
    verify_https()
