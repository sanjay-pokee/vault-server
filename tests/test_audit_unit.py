
import unittest
import json
from unittest.mock import patch, mock_open, MagicMock
from pathlib import Path
import sys
import os

# Add server to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server.audit import log_action
from tests.json_utils import load_json_with_comments

class TestAuditLog(unittest.TestCase):
    def setUp(self):
        # Load test cases
        data_path = Path(__file__).parent / "data" / "audit_cases.jsonc"
        self.test_cases = load_json_with_comments(data_path)

    @patch("server.audit._get_cipher")
    @patch("server.audit.datetime")
    def test_log_action(self, mock_datetime, mock_get_cipher):
        # Mock time to ensure consistent timestamp in tests
        mock_datetime.now.return_value.isoformat.return_value = "2026-01-01T12:00:00"
        
        # Mock cipher to return data as-is (simulating plaintext for the test assertions)
        mock_cipher = MagicMock()
        mock_cipher.encrypt.side_effect = lambda x: x
        mock_cipher.decrypt.side_effect = lambda x: x
        mock_get_cipher.return_value = mock_cipher

        for case in self.test_cases:
            with self.subTest(msg=case["name"]):
                print(f"Running audit test case: {case['name']}")
                
                # Mock file I/O
                # Initial state: empty list in bytes (encrypted/plaintext mock handles conversion)
                mock_file = mock_open(read_data=b'[]')
                
                with patch("builtins.open", mock_file):
                    log_action(case["username"], case["action"], case["details"])
                    
                    # Verify file was written
                    self.assertTrue(mock_file.called)
                    
                    # Inspect what was written
                    handle = mock_file()
                    written_bytes = b""
                    for call in handle.write.call_args_list:
                         written_bytes += call[0][0]
                    
                    written_content = written_bytes.decode()
                    
                    # Check if our expected entry is in the written content
                    expected = case["expected_log_entry"]
                    expected["timestamp"] = "2026-01-01T12:00:00"
                    
                    self.assertIn(expected["action"], written_content)
                    self.assertIn(expected["username"], written_content)

if __name__ == '__main__':
    unittest.main()
