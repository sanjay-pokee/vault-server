"""
Epic 1 Unit Tests - Admin Access Controls
Tests for User Story: 1.15

Validates that administrators cannot decrypt user data.
"""

import pytest
import json
from pathlib import Path


pytestmark = [pytest.mark.epic1, pytest.mark.security]


class TestAdminCannotReadPasswords:
    """US 1.15: Admin Cannot Read User Passwords"""
    
    def test_direct_file_access_shows_only_encrypted_data(
        self, temp_storage, test_user, sample_encrypted_blob
    ):
        """Test that admin with file access sees only ciphertext."""
        from server.storage import store_blob
        
        # User stores encrypted vault
        store_blob(test_user["username"], sample_encrypted_blob)
        
        # Admin reads file directly
        admin_view = temp_storage["data_dir"] / f"{test_user['username']}.json"
        raw_data = json.loads(admin_view.read_text())
        
        # Admin sees only encrypted fields
        assert "ciphertext" in raw_data
        assert "vault_salt" in raw_data
        assert "nonce" in raw_data
        
        # No plaintext password fields
        assert "password" not in raw_data
        assert "passwords" not in raw_data
    
    def test_no_decryption_functions_in_server(self):
        """Test that server code has no vault decryption capability."""
        import server.storage as storage
        import inspect
        
        # Get all functions in storage module
        functions = [
            name for name, obj in inspect.getmembers(storage)
            if inspect.isfunction(obj)
        ]
        
        # Should not have decrypt functions
        forbidden_names = ["decrypt", "decrypt_vault", "decrypt_blob"]
        for func_name in functions:
            assert func_name.lower() not in [f.lower() for f in forbidden_names], \
                f"Server should not have decryption function: {func_name}"
    
    def test_auth_db_contains_only_verifiers(
        self, temp_storage, test_user
    ):
        """Test that auth database stores only hashed verifiers."""
        from server.auth import register_user
        
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        
        # Admin reads auth database
        auth_data = json.loads(temp_storage["auth_db"].read_text())
        user_data = auth_data[test_user["username"]]
        
        # Should have verifier (hashed password derivative)
        assert "verifier" in user_data
        
        # Should NOT have plaintext password
        assert "password" not in user_data
        
        # Verifier should be hex-encoded (not plaintext)
        assert all(c in '0123456789abcdef' for c in user_data["verifier"].lower())
    
    def test_storage_files_unreadable_without_master_password(
        self, temp_storage, test_user, sample_encrypted_blob
    ):
        """Test that even with database access, passwords are unrecoverable."""
        from server.storage import store_blob
        from server.auth import register_user
        
        # Register user first
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        store_blob(test_user["username"], sample_encrypted_blob)
        
        # Admin reads all available data
        vault_data = json.loads(
            (temp_storage["data_dir"] / f"{test_user['username']}.json").read_text()
        )
        auth_data = json.loads(temp_storage["auth_db"].read_text())
        
        # Admin has:
        # - Encrypted vault (ciphertext, nonce, salt)
        # - User verifier (derived from password but not reversible)
        # - User auth salt
        
        # But admin CANNOT:
        # - Decrypt the vault (needs user's master password)
        # - Reverse the verifier (one-way hash via Argon2)
        # - Brute force easily (strong KDF parameters)
        
        # Verify ciphertext looks encrypted (hex, not plaintext)
        ciphertext = vault_data["ciphertext"]
        assert len(ciphertext) > 0
        assert all(c in '0123456789abcdef' for c in ciphertext.lower())
        
        # Verify verifier looks hashed (hex, not plaintext)
        verifier = auth_data[test_user["username"]]["verifier"]
        assert len(verifier) == 64  # 32 bytes hex
        assert all(c in '0123456789abcdef' for c in verifier.lower())
    
    def test_admin_access_audit(self, temp_storage, test_user, sample_encrypted_blob):
        """Test comprehensive admin access simulation.
        
        Simulates an admin with full file system access attempting
        to extract user passwords. Should fail at all levels.
        """
        from server.storage import store_blob
        from server.auth import register_user
        
        # User actions (simulated)
        register_user(
            test_user["username"],
            test_user["salt"],
            test_user["verifier"]
        )
        store_blob(test_user["username"], sample_encrypted_blob)
        
        # Admin access attempt
        findings = {}
        
        # 1. Check vault storage
        vault_file = temp_storage["data_dir"] / f"{test_user['username']}.json"
        vault_content = vault_file.read_text()
        findings["vault_has_plaintext"] = any(
            pattern in vault_content.lower()
            for pattern in ["password", "secret", "credential"]
        )
        
        # 2. Check auth database
        auth_file = temp_storage["auth_db"]
        auth_content = auth_file.read_text()
        findings["auth_has_password_field"] = '"password"' in auth_content
        
        # 3. Check for decryption capabilities
        import server.storage
        import server.auth
        findings["server_can_decrypt"] = (
            hasattr(server.storage, 'decrypt_vault') or
            hasattr(server.auth, 'decrypt')
        )
        
        # 4. Verify all data is protected
        assert findings["vault_has_plaintext"] is False, \
            "Vault contains plaintext sensitive data!"
        assert findings["auth_has_password_field"] is False, \
            "Auth DB contains password field!"
        assert findings["server_can_decrypt"] is False, \
            "Server has decryption capability!"
        
        # CONCLUSION: Admin cannot access user passwords
        # This validates zero-knowledge architecture (US 1.15)
