
import unittest
import json
import time
from unittest.mock import patch, MagicMock
from pathlib import Path

# Import the class to be tested
# We need to make sure the server module is in path or installed
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server.security import SecurityManager
from tests.json_utils import load_json_with_comments

class TestSecurityManager(unittest.TestCase):
    def setUp(self):
        self.security = SecurityManager()
        # Load test cases
        data_path = Path(__file__).parent / "data" / "rate_limit_cases.jsonc"
        self.test_cases = load_json_with_comments(data_path)

    def test_rate_limiting_scenarios(self):
        for case in self.test_cases:
            with self.subTest(msg=case["name"]):
                print(f"Running test case: {case['name']}")
                
                # Reset state
                self.security = SecurityManager()
                ip = "192.168.1.100"
                
                # Setup initial state
                initial_failures = case.get("initial_failures", 0)
                if initial_failures > 0:
                    # Manually set the state
                    self.security.failed_attempts[ip] = (initial_failures, time.time())
                    if initial_failures >= self.security.MAX_ATTEMPTS:
                        self.security.blocked_ips[ip] = time.time() + self.security.BLOCK_DURATION

                # Mock time if needed (for expiry checks)
                time_elapsed = case.get("time_elapsed", 0)
                
                with patch('time.time') as mock_time:
                    # Set current time. If we simulated expiry, advance time.
                    start_time = 1000.0
                    current_time = start_time + time_elapsed
                    mock_time.return_value = current_time
                    
                    # Fix the initial times in the object to be relative to start_time
                    if ip in self.security.failed_attempts:
                        count, _ = self.security.failed_attempts[ip]
                        self.security.failed_attempts[ip] = (count, start_time)
                    if ip in self.security.blocked_ips:
                        # blocked at start_time
                        self.security.blocked_ips[ip] = start_time + self.security.BLOCK_DURATION

                    # Action: Check Rate Limit
                    try:
                        self.security.check_rate_limit(ip)
                        # If we expect blocked but it's the "Threshold Reached" case, 
                        # it means we are ABOUT to be blocked, so check passes now.
                        if case.get("expected_blocked") and case.get("name") != "Threshold Reached":
                             self.fail(f"Should have been blocked but wasn't. Case: {case['name']}")
                    except ValueError as e:
                        if not case.get("expected_blocked"):
                            self.fail(f"Should NOT have been blocked. Error: {e}. Case: {case['name']}")
                        if "expected_error" in case:
                            self.assertIn(case["expected_error"], str(e))
                            return # If we expect block error, we stop here for this action
                    
                    # Action: Record Attempt (Success or Failure)
                    if not case.get("expected_blocked") or case.get("name") == "Threshold Reached":
                        if case.get("is_password_valid"):
                            # valid login, should reset failures? 
                            # The SecurityManager doesn't utilize "record_success", 
                            # usually the AuthManager handles success.
                            # But for this unit test, we just want to ensure we DON'T record a failure.
                            pass 
                        else:
                            # Simulate a failed login
                            self.security.record_failed_attempt(ip)
                        
                        # Verify validation
                        if "expected_attempts_recorded" in case:
                            count, _ = self.security.failed_attempts.get(ip, (0,0))
                            self.assertEqual(count, case["expected_attempts_recorded"])
                            
                        # If this was the attempt that triggered the block, verify block is now active
                        if case.get("expected_blocked") and case.get("name") == "Threshold Reached":
                             # Now check if it's blocked
                             try:
                                 self.security.check_rate_limit(ip)
                                 self.fail("Should be blocked after reaching threshold")
                             except ValueError:
                                 pass # Expected behavior

if __name__ == '__main__':
    unittest.main()
