
import unittest
import json
from unittest.mock import patch, mock_open, MagicMock
from pathlib import Path
import sys
import os

# Add server to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server.backup import create_backup, restore_backup
from tests.json_utils import load_json_with_comments

class TestBackup(unittest.TestCase):
    def setUp(self):
        # Load test cases
        data_path = Path(__file__).parent / "data" / "backup_cases.jsonc"
        self.test_cases = load_json_with_comments(data_path)

    @patch("server.backup.Fernet")
    @patch("server.backup.get_or_create_key")
    @patch("server.backup.Path.exists")
    @patch("server.backup.Path.mkdir")
    def test_backup_logic(self, mock_mkdir, mock_exists, mock_get_key, mock_fernet):
        # Mock Key and Fernet
        mock_get_key.return_value = b"fake_key_32_bytes_long_must_be_urlsafe=" 
        mock_cipher = MagicMock()
        mock_fernet.return_value = mock_cipher
        
        # Configure encryption/decryption mocks
        mock_cipher.encrypt.return_value = b"gAAAA_encrypted_content"
        
        # Determine if we are testing create or restore to set exists return value
        # But we loop through cases. Ideally we set side_effect based on case using a wrapper or just simple True
        mock_exists.return_value = True 

        for case in self.test_cases:
            with self.subTest(msg=case["name"]):
                print(f"Running backup test case: {case['name']}")
                
                if case["action"] == "CREATE":
                    # Mock reading user data file
                    # create_backup opens user_data_file (rb) and backup_filename (wb)
                    
                    # We need mock_open to handle multiple files.
                    # A common strategy is to have side_effect return different file handles based on name,
                    # or just return a generic handle that accepts everything if checking content strictly is hard.
                    
                    # Let's try to mock the specific data read.
                    # source data
                    user_data = json.dumps(case["blob_data"]).encode()
                    
                    # We can use a side_effect for open to return different file mocks
                    mock_source_file = mock_open(read_data=user_data)
                    mock_dest_file = mock_open()
                    
                    def open_side_effect(file, mode='r', **kwargs):
                        # Convert file to str just in case it's a Path object
                        str_file = str(file)
                        if "json" in str_file and "r" in mode:
                            return mock_source_file(file, mode, **kwargs)
                        elif "enc" in str_file and "w" in mode:
                            return mock_dest_file(file, mode, **kwargs)
                        else:
                            return MagicMock()

                    with patch("builtins.open", side_effect=open_side_effect):
                        filename = create_backup(case["username"])
                        
                        # Verify filename format
                        self.assertIn(case["expected_filename_prefix"], str(filename))
                        
                        # Verify encryption called
                        self.assertTrue(mock_cipher.encrypt.called)
                        
                        # Verify dest file write called
                        self.assertTrue(mock_dest_file().write.called)

                elif case["action"] == "RESTORE":
                     # Mock decryption to return the original blob string
                     original_blob_str = json.dumps(case["original_blob"])
                     mock_cipher.decrypt.return_value = original_blob_str.encode()
                     
                     # restore_backup opens backup_path (rb) and user_data_file (wb)
                     backup_content = case["file_content"].encode()
                     
                     mock_backup_file = mock_open(read_data=backup_content)
                     mock_restore_file = mock_open()
                     
                     def open_side_effect_restore(file, mode='r', **kwargs):
                        str_file = str(file)
                        if "enc" in str_file and "r" in mode:
                            return mock_backup_file(file, mode, **kwargs)
                        elif "json" in str_file and "w" in mode:
                            return mock_restore_file(file, mode, **kwargs)
                        else:
                            return MagicMock()

                     # We also need to patch Path(backup_path).name to ensure it starts with backup_username_
                     # But restore_backup takes a string path.
                     # It does: path = Path(backup_path); filename = path.name
                     # Since we pass strings, Path(str) works. We just need to ensure the string fits.
                     
                     with patch("builtins.open", side_effect=open_side_effect_restore):
                         restore_backup(case["filename"], case["username"])
                         
                         # Verify decrypt called
                         self.assertTrue(mock_cipher.decrypt.called)
                         
                         # Verify restore file write called
                         self.assertTrue(mock_restore_file().write.called)
                         # We could verify the content written matches original_blob
                         # args = mock_restore_file().write.call_args[0][0]
                         # self.assertEqual(args, original_blob_str.encode())

if __name__ == '__main__':
    unittest.main()
