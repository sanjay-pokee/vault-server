"""
Epic 1 Unit Tests - Storage Module
Tests for User Stories: 1.7

Validates encrypted-only storage and breach resistance.
"""

import pytest
import json
from server.storage import store_blob, load_blob


pytestmark = pytest.mark.epic1


class TestEncryptedStorage:
    """US 1.7: Server Stores Only Encrypted Blobs"""
    
    @pytest.mark.storage
    def test_store_blob_saves_to_file(self, temp_storage, test_user, sample_encrypted_blob):
        """Test that store_blob() persists data to file system."""
        store_blob(test_user["username"], sample_encrypted_blob)
        
        # Verify file was created
        user_file = temp_storage["data_dir"] / f"{test_user['username']}.json"
        assert user_file.exists()
    
    @pytest.mark.storage
    def test_stored_blob_contains_only_encrypted_fields(
        self, temp_storage, test_user, sample_encrypted_blob
    ):
        """Test that stored data contains only encryption metadata."""
        store_blob(test_user["username"], sample_encrypted_blob)
        
        # Read raw file content
        user_file = temp_storage["data_dir"] / f"{test_user['username']}.json"
        raw_data = json.loads(user_file.read_text())
        
        # Verify expected fields present
        assert "vault_salt" in raw_data
        assert "nonce" in raw_data
        assert "ciphertext" in raw_data
        
        # Verify no forbidden plaintext fields
        forbidden_fields = ["password", "passwords", "username", "key", "secret"]
        for field in forbidden_fields:
            assert field not in raw_data.keys()
    
    @pytest.mark.storage
    def test_stored_blob_never_contains_plaintext(
        self, temp_storage, test_user, sample_encrypted_blob
    ):
        """Test that stored ciphertext is hex-encoded, not plaintext."""
        store_blob(test_user["username"], sample_encrypted_blob)
        
        # Read raw file content
        user_file = temp_storage["data_dir"] / f"{test_user['username']}.json"
        raw_content = user_file.read_text()
        
        # Should not contain common plaintext patterns
        plaintext_patterns = [
            "mypassword",
            "password123",
            "secret",
            "credential",
            "login",
        ]
        
        for pattern in plaintext_patterns:
            assert pattern.lower() not in raw_content.lower()
    
    @pytest.mark.storage
    def test_load_blob_returns_none_for_nonexistent_user(self, temp_storage):
        """Test that loading non-existent user returns None."""
        blob = load_blob("nonexistent_user")
        assert blob is None
    
    @pytest.mark.storage
    def test_load_blob_recovers_stored_data(
        self, temp_storage, test_user, sample_encrypted_blob
    ):
        """Test that load_blob() correctly retrieves stored data."""
        store_blob(test_user["username"], sample_encrypted_blob)
        
        recovered_blob = load_blob(test_user["username"])
        
        assert recovered_blob == sample_encrypted_blob
    
    @pytest.mark.storage
    def test_load_blob_handles_corrupted_json(self, temp_storage, test_user):
        """Test that corrupted JSON is handled gracefully."""
        # Create corrupted JSON file
        user_file = temp_storage["data_dir"] / f"{test_user['username']}.json"
        user_file.write_text("{corrupted json content")
        
        blob = load_blob(test_user["username"])
        assert blob is None
    
    @pytest.mark.storage
    def test_load_blob_handles_empty_file(self, temp_storage, test_user):
        """Test that empty files are handled gracefully."""
        # Create empty file
        user_file = temp_storage["data_dir"] / f"{test_user['username']}.json"
        user_file.write_text("")
        
        blob = load_blob(test_user["username"])
        assert blob is None


class TestBreachResistance:
    """US 1.7: Storage Breach Simulation"""
    
    @pytest.mark.storage
    @pytest.mark.security
    def test_raw_file_shows_only_ciphertext(
        self, temp_storage, test_user, sample_encrypted_blob
    ):
        """Test that direct file inspection reveals no plaintext."""
        store_blob(test_user["username"], sample_encrypted_blob)
        
        # Read file as an attacker would
        user_file = temp_storage["data_dir"] / f"{test_user['username']}.json"
        raw_bytes = user_file.read_bytes()
        raw_text = raw_bytes.decode('utf-8')
        
        # Verify file is JSON (structured)
        data = json.loads(raw_text)
        
        # All values should be hex strings (even length, hex chars only)
        for key, value in data.items():
            assert isinstance(value, str)
            assert len(value) % 2 == 0  # Hex strings have even length
            assert all(c in '0123456789abcdef' for c in value.lower())
    
    @pytest.mark.storage
    @pytest.mark.security
    def test_storage_files_isolated_per_user(
        self, temp_storage, sample_encrypted_blob
    ):
        """Test that users have separate storage files."""
        user1 = "alice"
        user2 = "bob"
        
        store_blob(user1, sample_encrypted_blob)
        store_blob(user2, sample_encrypted_blob)
        
        # Verify separate files created
        alice_file = temp_storage["data_dir"] / f"{user1}.json"
        bob_file = temp_storage["data_dir"] / f"{user2}.json"
        
        assert alice_file.exists()
        assert bob_file.exists()
        assert alice_file != bob_file
    
    @pytest.mark.storage
    @pytest.mark.security
    def test_no_human_readable_passwords_in_storage(
        self, temp_storage, test_user, sample_encrypted_blob
    ):
        """Test storage for absence of common password patterns."""
        store_blob(test_user["username"], sample_encrypted_blob)
        
        # Read all files in data directory
        all_content = ""
        for file_path in temp_storage["data_dir"].glob("*.json"):
            all_content += file_path.read_text()
        
        # Common password patterns that should NEVER appear
        forbidden_patterns = [
            "password",
            "pass123",
            "admin",
            "12345",
            "qwerty",
            "letmein",
        ]
        
        for pattern in forbidden_patterns:
            # Should not find these patterns (case-insensitive)
            assert pattern.lower() not in all_content.lower(), \
                f"Found forbidden pattern '{pattern}' in storage!"
