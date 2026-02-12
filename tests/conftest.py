"""
pytest configuration and fixtures for Epic 1 unit tests.
Provides test utilities for authentication, storage isolation, and API testing.
"""

import pytest
import json
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from server.api import app
from server.auth import SESSIONS, AUTH_DB


@pytest.fixture
def client():
    """FastAPI test client for API integration tests."""
    return TestClient(app)


@pytest.fixture
def test_user():
    """Sample user credentials for testing.
    
    Returns dict with username, password, salt, and verifier.
    Password is never stored - only used for test documentation.
    """
    return {
        "username": "testuser",
        "password": "TestPassword123!",  # Only for test reference, never sent to server
        "salt": "0123456789abcdef0123456789abcdef",  # 16 bytes hex
        "verifier": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",  # 32 bytes hex
    }


@pytest.fixture
def temp_storage(monkeypatch, tmp_path):
    """Isolate file storage for tests.
    
    Redirects all storage operations to a temporary directory
    to prevent test pollution of real data.
    """
    # Create temp directories for test isolation
    temp_data_dir = tmp_path / "data"
    temp_data_dir.mkdir()
    
    temp_auth_db = tmp_path / "auth_db.json"
    temp_auth_db.write_text("{}")
    
    # Patch storage module paths
    import server.storage as storage
    monkeypatch.setattr(storage, "DATA_DIR", temp_data_dir)
    
    # Patch auth module paths
    import server.auth as auth
    monkeypatch.setattr(auth, "AUTH_DB", temp_auth_db)
    
    return {
        "data_dir": temp_data_dir,
        "auth_db": temp_auth_db,
    }


@pytest.fixture(autouse=True)
def clear_sessions():
    """Clear session data before and after each test."""
    SESSIONS.clear()
    yield
    SESSIONS.clear()


@pytest.fixture
def authenticated_user(client, temp_storage, test_user):
    """Create a registered and authenticated user, returns token.
    
    Useful for tests that need a valid session token.
    """
    # Register user
    client.post(
        "/register",
        json={
            "username": test_user["username"],
            "salt": test_user["salt"],
            "verifier": test_user["verifier"],
        }
    )
    
    # Login to get token
    response = client.post(
        "/login",
        json={
            "username": test_user["username"],
            "verifier": test_user["verifier"],
        }
    )
    
    token = response.json()["token"]
    return {
        "token": token,
        "username": test_user["username"],
    }


@pytest.fixture
def sample_encrypted_blob():
    """Sample encrypted vault blob for testing.
    
    This represents what the server should store - only encrypted data.
    """
    return {
        "vault_salt": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        "nonce": "112233445566778899aabbccddeeff00112233445566778899aabbcc",
        "ciphertext": "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabe0011223344556677",
    }
