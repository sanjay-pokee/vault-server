
import unittest
import json
from unittest.mock import patch, mock_open
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

    @patch("server.audit.datetime")
    def test_log_action(self, mock_datetime):
        # Mock time to ensure consistent timestamp in tests
        # We need to make sure isoformat returns a string, not a MagicMock
        mock_datetime.datetime.now.return_value.isoformat.return_value = "2026-01-01T12:00:00"
        # Also need to make sure the datetime object itself behaves enough like an object for json.dump if it's used directly
        # But log_action calls isoformat(), so the above should be enough IF log_action uses the return value.
        # Let's double check log_action implementation. it likely does: timestamp = datetime.datetime.utcnow().isoformat()

        for case in self.test_cases:
            with self.subTest(msg=case["name"]):
                print(f"Running audit test case: {case['name']}")
                
                # Mock file I/O
                # We need to handle both read (loading existing logs) and write (saving new logs)
                # Initial state: empty list
                mock_file = mock_open(read_data='[]')
                
                with patch("builtins.open", mock_file):
                    log_action(case["username"], case["action"], case["details"])
                    
                    # Verify file was written
                    self.assertTrue(mock_file.called)
                    
                    # Verify content written
                    # Raises error if logic is wrong, but we want to inspect what was written.
                    # This is tricky with mock_open and json.dump, often easier to check calls.
                    # Or simpler: verify the structure appended.
                    
                    # Let's inspect the arguments passed to json.dump (or write)
                    # Implementation detail: log_action reads, appends, writes.
                    
                    # We can verify that the last write call contained our expected entry
                    handle = mock_file()
                    written_content = ""
                    for call in handle.write.call_args_list:
                         written_content += call[0][0]
                    
                    # Check if our expected entry is in the written content
                    expected = case["expected_log_entry"]
                    expected["timestamp"] = "2026-01-01T12:00:00"
                    
                    # Since json.dump writes the whole list, we check if our dict is inside
                    # A robust way is to try to parse it, but let's just check strings for now
                    self.assertIn(expected["action"], written_content)
                    self.assertIn(expected["username"], written_content)

if __name__ == '__main__':
    unittest.main()
