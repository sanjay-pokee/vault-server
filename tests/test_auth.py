"""
Epic 1 Unit Tests - Authentication Module
Tests for User Stories: 1.1, 1.2, 1.6, 1.10, 1.14

Validates zero-knowledge authentication, MFA, and secure session management.
"""

import pytest
from server.auth import (
    register_user,
    get_auth_salt,
    login_user,
    require_auth,
    setup_mfa,
    verify_mfa,
    check_mfa_enabled,
    disable_mfa,
    SESSIONS,
)


pytestmark = pytest.mark.epic1


class TestUserRegistration:
    """US 1.1: Account Creation"""
    
    @pytest.mark.auth
    def test_register_user_creates_account(self, temp_storage, test_user):
        """Test that registration creates user with salt and verifier."""
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        # Verify user was created
        salt = get_auth_salt(test_user["username"])
        assert salt == test_user["salt"]
    
    @pytest.mark.auth
    def test_register_user_rejects_duplicate(self, temp_storage, test_user):
        """Test that duplicate usernames are rejected."""
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        # Attempt to register same username again
        with pytest.raises(ValueError, match="User exists"):
            register_user(
                test_user["username"],
                test_user["salt"],
                test_user["verifier"]
            )
    
    @pytest.mark.auth
    def test_user_initialized_with_empty_vault(self, temp_storage, test_user):
        """Test that new users start with empty/no vault data."""
        from server.storage import load_blob
        
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        # New user should have no vault blob yet
        blob = load_blob(test_user["username"])
        assert blob is None


class TestMasterPasswordSecurity:
    """US 1.2: Master Password Never Sent to Server"""
    
    @pytest.mark.auth
    @pytest.mark.security
    def test_register_only_accepts_verifier(self, temp_storage):
        """Test that register_user() has no password parameter."""
        import inspect
        sig = inspect.signature(register_user)
        params = list(sig.parameters.keys())
        
        assert "password" not in params
        assert "salt" in params
        assert "verifier" in params
    
    @pytest.mark.auth
    @pytest.mark.security
    def test_login_only_accepts_verifier(self, temp_storage):
        """Test that login_user() has no password parameter."""
        import inspect
        sig = inspect.signature(login_user)
        params = list(sig.parameters.keys())
        
        assert "password" not in params
        assert "verifier" in params
    
    @pytest.mark.auth
    @pytest.mark.security
    def test_no_password_in_storage(self, temp_storage, test_user):
        """Test that auth database never stores plaintext passwords."""
        import json
        
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        # Read raw auth database file
        auth_data = json.loads(temp_storage["auth_db"].read_text())
        user_data = auth_data[test_user["username"]]
        
        # Verify no password field exists
        assert "password" not in user_data
        assert "salt" in user_data
        assert "verifier" in user_data


class TestVerifierAuthentication:
    """US 1.6: Authentication Without Key Exposure"""
    
    @pytest.mark.auth
    def test_login_validates_verifier(self, temp_storage, test_user):
        """Test that login succeeds with correct verifier."""
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        token = login_user(test_user["username"], test_user["verifier"])
        
        assert token is not None
        assert len(token) == 64  # 32 bytes hex = 64 chars
    
    @pytest.mark.auth
    def test_login_rejects_invalid_verifier(self, temp_storage, test_user):
        """Test that login fails with wrong verifier."""
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        wrong_verifier = "0" * 64
        with pytest.raises(ValueError, match="Invalid credentials"):
            login_user(test_user["username"], wrong_verifier)
    
    @pytest.mark.auth
    def test_login_creates_session(self, temp_storage, test_user):
        """Test that successful login creates session token."""
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        token = login_user(test_user["username"], test_user["verifier"])
        
        # Verify session exists
        assert token in SESSIONS
        assert SESSIONS[token] == test_user["username"]
    
    @pytest.mark.auth
    def test_require_auth_validates_token(self, temp_storage, test_user):
        """Test that require_auth() validates session tokens."""
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        token = login_user(test_user["username"], test_user["verifier"])
        
        # Valid token should return username
        username = require_auth(token)
        assert username == test_user["username"]
    
    @pytest.mark.auth
    def test_require_auth_rejects_invalid_token(self, temp_storage):
        """Test that require_auth() rejects invalid tokens."""
        fake_token = "faketo" + "0" * 58
        
        with pytest.raises(ValueError, match="Unauthorized"):
            require_auth(fake_token)


class TestInformationLeakagePrevention:
    """US 1.10: Failed Auth Doesn't Leak Crypto Info"""
    
    @pytest.mark.auth
    @pytest.mark.security
    def test_get_auth_salt_returns_none_for_unknown_user(self, temp_storage):
        """Test that unknown users don't reveal whether they exist."""
        salt = get_auth_salt("nonexistent_user")
        assert salt is None
    
    @pytest.mark.auth
    @pytest.mark.security
    def test_failed_login_raises_generic_error(self, temp_storage, test_user):
        """Test that failed login doesn't leak whether user exists."""
        # Login without registering first
        with pytest.raises(ValueError) as exc_info:
            login_user(test_user["username"], test_user["verifier"])
        
        # Error message should be generic
        error_msg = str(exc_info.value)
        assert "salt" not in error_msg.lower()
        assert "verifier" not in error_msg.lower()
        assert "key" not in error_msg.lower()
    
    @pytest.mark.auth
    @pytest.mark.security
    def test_wrong_verifier_raises_generic_error(self, temp_storage, test_user):
        """Test that wrong verifier doesn't leak crypto details."""
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        with pytest.raises(ValueError) as exc_info:
            login_user(test_user["username"], "wrong" + "0" * 60)
        
        # Error message should be generic
        error_msg = str(exc_info.value)
        assert "correct" not in error_msg.lower()
        assert "expected" not in error_msg.lower()


class TestMFAFunctionality:
    """US 1.14: Multi-Factor Authentication"""
    
    @pytest.mark.mfa
    def test_setup_mfa_generates_secret(self, temp_storage, test_user):
        """Test that MFA setup generates TOTP secret."""
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        mfa_data = setup_mfa(test_user["username"])
        
        assert "secret" in mfa_data
        assert len(mfa_data["secret"]) == 32  # Base32 encoded secret
    
    @pytest.mark.mfa
    def test_setup_mfa_generates_qr_code(self, temp_storage, test_user):
        """Test that MFA setup returns QR code data."""
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        mfa_data = setup_mfa(test_user["username"])
        
        assert "qr_code" in mfa_data
        assert "provisioning_uri" in mfa_data
        assert mfa_data["qr_code"].startswith("data:image/png;base64,")
    
    @pytest.mark.mfa
    def test_setup_mfa_generates_backup_codes(self, temp_storage, test_user):
        """Test that MFA setup generates recovery backup codes."""
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        mfa_data = setup_mfa(test_user["username"])
        
        assert "backup_codes" in mfa_data
        assert len(mfa_data["backup_codes"]) == 10
        
        # Verify format: XXXX-XXXX
        for code in mfa_data["backup_codes"]:
            assert len(code) == 9  # 4 + 1 (dash) + 4
            assert "-" in code
    
    @pytest.mark.mfa
    def test_verify_mfa_accepts_valid_code(self, temp_storage, test_user):
        """Test that valid TOTP codes are accepted."""
        import pyotp
        
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        mfa_data = setup_mfa(test_user["username"])
        secret = mfa_data["secret"]
        
        # Generate current TOTP code
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        
        # Verify code
        result = verify_mfa(test_user["username"], current_code)
        assert result is True
    
    @pytest.mark.mfa
    def test_verify_mfa_rejects_invalid_code(self, temp_storage, test_user):
        """Test that invalid TOTP codes are rejected."""
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        setup_mfa(test_user["username"])
        
        # Try invalid code
        result = verify_mfa(test_user["username"], "000000")
        assert result is False
    
    @pytest.mark.mfa
    def test_verify_mfa_enables_on_first_success(self, temp_storage, test_user):
        """Test that MFA is enabled after first successful verification."""
        import pyotp
        
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        # Initially MFA should be disabled
        assert check_mfa_enabled(test_user["username"]) is False
        
        mfa_data = setup_mfa(test_user["username"])
        totp = pyotp.TOTP(mfa_data["secret"])
        
        # Verify code (should enable MFA)
        verify_mfa(test_user["username"], totp.now())
        
        # Now MFA should be enabled
        assert check_mfa_enabled(test_user["username"]) is True
    
    @pytest.mark.mfa
    def test_check_mfa_enabled_returns_status(self, temp_storage, test_user):
        """Test that MFA status can be checked."""
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        # Initially disabled
        assert check_mfa_enabled(test_user["username"]) is False
        
        # After setup, still disabled until verified
        setup_mfa(test_user["username"])
        assert check_mfa_enabled(test_user["username"]) is False
    
    @pytest.mark.mfa
    def test_disable_mfa_clears_data(self, temp_storage, test_user):
        """Test that disabling MFA removes all MFA data."""
        import json
        import pyotp
        
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        # Setup and enable MFA
        mfa_data = setup_mfa(test_user["username"])
        totp = pyotp.TOTP(mfa_data["secret"])
        verify_mfa(test_user["username"], totp.now())
        
        assert check_mfa_enabled(test_user["username"]) is True
        
        # Disable MFA
        result = disable_mfa(test_user["username"])
        assert result is True
        assert check_mfa_enabled(test_user["username"]) is False
        
        # Verify data cleared from storage
        auth_data = json.loads(temp_storage["auth_db"].read_text())
        user_data = auth_data[test_user["username"]]
        
        assert user_data["mfa_secret"] is None
        assert user_data["mfa_enabled"] is False
        assert user_data["backup_codes"] == []
