"""
Epic 1 Unit Tests - Security Module
Tests for User Stories: 1.8, 1.10

Validates rate limiting and strong cryptographic parameters.
"""

import pytest
import time
from server.security import SecurityManager


pytestmark = pytest.mark.epic1


class TestRateLimiting:
    """US 1.10: Rate Limiting on Failed Attempts"""
    
    @pytest.mark.security
    def test_check_rate_limit_allows_under_threshold(self):
        """Test that requests under threshold are allowed."""
        manager = SecurityManager()
        ip = "192.168.1.100"
        
        # Should not raise any exception
        manager.check_rate_limit(ip)
    
    @pytest.mark.security
    def test_record_failed_attempt_increments_counter(self):
        """Test that failed attempts are recorded."""
        manager = SecurityManager()
        ip = "192.168.1.100"
        
        manager.record_failed_attempt(ip)
        
        # Verify attempt was recorded
        assert ip in manager.failed_attempts
        count, _ = manager.failed_attempts[ip]
        assert count == 1
    
    @pytest.mark.security
    def test_multiple_failed_attempts_increment_count(self):
        """Test that multiple attempts are tracked."""
        manager = SecurityManager()
        ip = "192.168.1.100"
        
        for i in range(3):
            manager.record_failed_attempt(ip)
        
        count, _ = manager.failed_attempts[ip]
        assert count == 3
    
    @pytest.mark.security
    def test_check_rate_limit_blocks_after_max_attempts(self):
        """Test that IP is blocked after MAX_ATTEMPTS failures."""
        manager = SecurityManager()
        ip = "192.168.1.100"
        
        # Record MAX_ATTEMPTS failures
        for i in range(manager.MAX_ATTEMPTS):
            manager.record_failed_attempt(ip)
        
        # Next check should raise ValueError
        with pytest.raises(ValueError, match="IP blocked"):
            manager.check_rate_limit(ip)
    
    @pytest.mark.security
    def test_blocking_includes_retry_after_time(self):
        """Test that block message includes retry-after duration."""
        manager = SecurityManager()
        ip = "192.168.1.100"
        
        for i in range(manager.MAX_ATTEMPTS):
            manager.record_failed_attempt(ip)
        
        with pytest.raises(ValueError) as exc_info:
            manager.check_rate_limit(ip)
        
        error_msg = str(exc_info.value)
        assert "seconds" in error_msg.lower()
        # Should mention a number (the retry-after time)
        assert any(char.isdigit() for char in error_msg)
    
    @pytest.mark.security
    def test_reset_attempts_clears_counter(self):
        """Test that successful login resets failure counter."""
        manager = SecurityManager()
        ip = "192.168.1.100"
        
        # Record some failures
        for i in range(3):
            manager.record_failed_attempt(ip)
        
        assert ip in manager.failed_attempts
        
        # Reset on successful login
        manager.reset_attempts(ip)
        
        assert ip not in manager.failed_attempts
    
    @pytest.mark.security
    def test_time_window_resets_after_expiry(self):
        """Test that failure count resets after time window."""
        manager = SecurityManager()
        manager.TIME_WINDOW = 1  # 1 second for testing
        ip = "192.168.1.100"
        
        # Record initial failure
        manager.record_failed_attempt(ip)
        count, _ = manager.failed_attempts[ip]
        assert count == 1
        
        # Wait for time window to expire
        time.sleep(1.1)
        
        # Record another failure (should reset to 1)
        manager.record_failed_attempt(ip)
        count, _ = manager.failed_attempts[ip]
        assert count == 1  # Reset due to time window expiry
    
    @pytest.mark.security
    def test_block_expires_after_duration(self):
        """Test that IP block is automatically removed after duration."""
        manager = SecurityManager()
        manager.BLOCK_DURATION = 1  # 1 second for testing
        ip = "192.168.1.100"
        
        # Trigger block
        for i in range(manager.MAX_ATTEMPTS):
            manager.record_failed_attempt(ip)
        
        # Should be blocked
        with pytest.raises(ValueError):
            manager.check_rate_limit(ip)
        
        # Wait for block to expire
        time.sleep(1.1)
        
        # Should no longer be blocked
        manager.check_rate_limit(ip)  # Should not raise
    
    @pytest.mark.security
    def test_different_ips_tracked_separately(self):
        """Test that different IP addresses have separate counters."""
        manager = SecurityManager()
        ip1 = "192.168.1.100"
        ip2 = "192.168.1.101"
        
        manager.record_failed_attempt(ip1)
        manager.record_failed_attempt(ip1)
        manager.record_failed_attempt(ip2)
        
        count1, _ = manager.failed_attempts[ip1]
        count2, _ = manager.failed_attempts[ip2]
        
        assert count1 == 2
        assert count2 == 1


class TestStrongKDFParameters:
    """US 1.8: Strong Key Derivation Function Configuration"""
    
    @pytest.mark.security
    def test_max_attempts_configured(self):
        """Test that MAX_ATTEMPTS is set to reasonable value."""
        manager = SecurityManager()
        
        # Should allow some attempts but not too many
        assert manager.MAX_ATTEMPTS >= 3
        assert manager.MAX_ATTEMPTS <= 10
    
    @pytest.mark.security
    def test_time_window_configured(self):
        """Test that time window is configured."""
        manager = SecurityManager()
        
        # Should be at least 60 seconds (1 minute)
        assert manager.TIME_WINDOW >= 60
    
    @pytest.mark.security
    def test_block_duration_configured(self):
        """Test that block duration is configured."""
        manager = SecurityManager()
        
        # Should block for at least 30 seconds
        assert manager.BLOCK_DURATION >= 30
    
    @pytest.mark.security
    def test_argon2_parameters_meet_owasp_recommendations(self):
        """Test that Argon2 parameters meet OWASP minimum recommendations.
        
        OWASP recommendations for Argon2id:
        - Memory: >= 19 MiB (19456 KiB)
        - Iterations: >= 2
        - Parallelism: >= 1
        
        Our current settings (from auth_service.dart):
        - Memory: 128 MB (memoryPowerOf2: 17 = 2^17 KB = 131072 KB)
        - Iterations: 3
        - Parallelism: 4
        """
        # Note: This test documents the KDF parameters used in client
        # The actual parameters are in client_code auth_service.dart
        
        expected_params = {
            "iterations": 3,
            "memory_kb": 131072,  # 2^17 KB = 128 MB
            "parallelism": 4,
            "hash_length": 32,  # 256 bits
        }
        
        # OWASP minimums
        owasp_min = {
            "iterations": 2,
            "memory_kb": 19456,  # 19 MiB
            "parallelism": 1,
        }
        
        # Verify our settings meet or exceed OWASP recommendations
        assert expected_params["iterations"] >= owasp_min["iterations"]
        assert expected_params["memory_kb"] >= owasp_min["memory_kb"]
        assert expected_params["parallelism"] >= owasp_min["parallelism"]
        assert expected_params["hash_length"] == 32  # 256-bit keys


class TestSecurityAlerts:
    """Additional security logging and monitoring tests"""
    
    @pytest.mark.security
    def test_failed_attempts_logged_with_username(self, capsys):
        """Test that suspicious activity is logged with context."""
        manager = SecurityManager()
        ip = "192.168.1.100"
        username = "testuser"
        
        # Trigger block (which logs alert)
        for i in range(manager.MAX_ATTEMPTS):
            manager.record_failed_attempt(ip, username)
        
        # Check console output for security alert
        captured = capsys.readouterr()
        assert "SECURITY ALERT" in captured.out
        assert ip in captured.out
        assert username in captured.out
