
import os
import shutil
import json
import tempfile
from pathlib import Path
from unittest.mock import patch
from server.backup import create_backup, restore_backup

def test_backup_flow():
    # Create temp directory for test
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        temp_data_dir = temp_path / "data"
        temp_auth_db = temp_path / "auth_db.json"
        
        # Setup dummy data
        temp_data_dir.mkdir()
        (temp_data_dir / "test_user.json").write_text('{"content": "secret"}')
        temp_auth_db.write_text('{"test_user": {"salt": "s", "verifier": "v"}}')
        
        print("Created dummy data in temp dir.")
        
        # Patch the paths in server.backup
        with patch('server.backup.DATA_DIR', temp_data_dir), \
             patch('server.backup.AUTH_DB', temp_auth_db), \
             patch('server.backup.BACKUP_DIR', temp_path / "backups"):
            
            # Create backup
            backup_path = create_backup()
            print(f"Backup created at: {backup_path}")
            
            # Verify backup exists
            if not os.path.exists(backup_path):
                print("Backup file not found!")
                return
                
            # Modify data
            (temp_data_dir / "test_user.json").write_text('{"content": "corrupted"}')
            temp_auth_db.write_text('{}')
            print("Modified data (simulating corruption).")
            
            # Restore
            restore_backup(backup_path)
            print("Restored backup.")
            
            # Verify restoration
            restored_data = (temp_data_dir / "test_user.json").read_text()
            restored_auth = temp_auth_db.read_text()
            
            if '"content": "secret"' in restored_data and '"test_user"' in restored_auth:
                print("SUCCESS: Data verified!")
            else:
                print("FAILURE: Data mismatch!")
                print(f"Data: {restored_data}")
                print(f"Auth: {restored_auth}")

if __name__ == "__main__":
    test_backup_flow()
