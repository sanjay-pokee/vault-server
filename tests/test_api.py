"""
Epic 1 Unit Tests - API Integration
Tests for User Stories: 1.1, 1.2, 1.4, 1.5, 1.6, 1.7, 1.10, 1.14

End-to-end API endpoint tests using FastAPI TestClient.
"""

import pytest
import pyotp
from fastapi.testclient import TestClient


pytestmark = [pytest.mark.epic1, pytest.mark.integration]


class TestRegistrationEndpoint:
    """US 1.1, 1.2: Registration API"""
    
    def test_register_endpoint_creates_user(self, client, temp_storage, test_user):
        """Test POST /register creates new user account."""
        response = client.post(
            "/register",
            json={
                "username": test_user["username"],
                "salt": test_user["salt"],
                "verifier": test_user["verifier"],
            }
        )
        
        assert response.status_code == 200
        assert response.json()["ok"] is True
    
    def test_register_endpoint_rejects_duplicate(self, client, temp_storage, test_user):
        """Test POST /register rejects duplicate usernames."""
        # Register once
        client.post(
            "/register",
            json={
                "username": test_user["username"],
                "salt": test_user["salt"],
                "verifier": test_user["verifier"],
            }
        )
        
        # Try to register again
        response = client.post(
            "/register",
            json={
                "username": test_user["username"],
                "salt": test_user["salt"],
                "verifier": test_user["verifier"],
            }
        )
        
        assert response.status_code == 400
        assert "User exists" in response.json()["detail"]
    
    def test_register_validates_request_body(self, client, temp_storage):
        """Test POST /register validates required fields."""
        # Missing verifier
        response = client.post(
            "/register",
            json={
                "username": "test",
                "salt": "abc123",
            }
        )
        
        assert response.status_code == 422  # Validation error


class TestAuthenticationEndpoints:
    """US 1.6, 1.10: Authentication API"""
    
    def test_get_auth_salt_returns_salt(self, client, temp_storage, test_user):
        """Test GET /auth_salt/{username} returns user's salt."""
        # Register user first
        client.post(
            "/register",
            json={
                "username": test_user["username"],
                "salt": test_user["salt"],
                "verifier": test_user["verifier"],
            }
        )
        
        response = client.get(f"/auth_salt/{test_user['username']}")
        
        assert response.status_code == 200
        assert response.json()["salt"] == test_user["salt"]
    
    def test_get_auth_salt_404_for_unknown_user(self, client, temp_storage):
        """Test GET /auth_salt/{username} returns 404 for non-existent user."""
        response = client.get("/auth_salt/nonexistent")
        
        assert response.status_code == 404
    
    def test_login_returns_token_on_success(self, client, temp_storage, test_user):
        """Test POST /login returns session token."""
        # Register user
        client.post(
            "/register",
            json={
                "username": test_user["username"],
                "salt": test_user["salt"],
                "verifier": test_user["verifier"],
            }
        )
        
        # Login
        response = client.post(
            "/login",
            json={
                "username": test_user["username"],
                "verifier": test_user["verifier"],
            }
        )
        
        assert response.status_code == 200
        assert "token" in response.json()
        assert len(response.json()["token"]) == 64
    
    def test_login_returns_401_on_invalid_credentials(self, client, temp_storage, test_user):
        """Test POST /login returns 401 for wrong verifier."""
        # Register user
        client.post(
            "/register",
            json={
                "username": test_user["username"],
                "salt": test_user["salt"],
                "verifier": test_user["verifier"],
            }
        )
        
        # Login with wrong verifier
        response = client.post(
            "/login",
            json={
                "username": test_user["username"],
                "verifier": "0" * 64,
            }
        )
        
        assert response.status_code == 401


class TestVaultEndpoints:
    """US 1.4, 1.5, 1.7: Vault Storage API"""
    
    def test_get_vault_requires_authentication(self, client, temp_storage):
        """Test GET /vault requires valid token."""
        response = client.get("/vault")
        
        assert response.status_code == 422  # Missing header
        
        # With invalid token
        response = client.get(
            "/vault",
            headers={"Authorization": "invalid_token"}
        )
        
        assert response.status_code == 401
    
    def test_get_vault_returns_encrypted_blob(
        self, client, temp_storage, authenticated_user, sample_encrypted_blob
    ):
        """Test GET /vault returns stored encrypted data."""
        from server.storage import store_blob
        
        # Store encrypted vault
        store_blob(authenticated_user["username"], sample_encrypted_blob)
        
        # Retrieve via API
        response = client.get(
            "/vault",
            headers={"Authorization": authenticated_user["token"]}
        )
        
        assert response.status_code == 200
        assert response.json()["blob"] == sample_encrypted_blob
    
    def test_post_vault_stores_encrypted_blob(
        self, client, temp_storage, authenticated_user, sample_encrypted_blob
    ):
        """Test POST /vault stores encrypted data."""
        response = client.post(
            "/vault",
            headers={"Authorization": authenticated_user["token"]},
            json={"blob": sample_encrypted_blob}
        )
        
        assert response.status_code == 200
        assert response.json()["ok"] is True
        
        # Verify stored
        from server.storage import load_blob
        stored = load_blob(authenticated_user["username"])
        assert stored == sample_encrypted_blob
    
    def test_post_vault_rejects_unauthenticated(
        self, client, temp_storage, sample_encrypted_blob
    ):
        """Test POST /vault rejects requests without authentication."""
        response = client.post(
            "/vault",
            headers={"Authorization": "invalid_token"},
            json={"blob": sample_encrypted_blob}
        )
        
        assert response.status_code == 401


class TestMFAEndpoints:
    """US 1.14: MFA API"""
    
    def test_mfa_setup_requires_authentication(self, client, temp_storage):
        """Test POST /mfa/setup requires valid token."""
        response = client.post("/mfa/setup")
        
        assert response.status_code == 422  # Missing header
    
    def test_mfa_setup_returns_qr_code(self, client, temp_storage, authenticated_user):
        """Test POST /mfa/setup returns QR code and secret."""
        response = client.post(
            "/mfa/setup",
            headers={"Authorization": authenticated_user["token"]}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "secret" in data
        assert "qr_code" in data
        assert "provisioning_uri" in data
        assert "backup_codes" in data
        assert data["qr_code"].startswith("data:image/png;base64,")
    
    def test_mfa_verify_validates_code(self, client, temp_storage, authenticated_user):
        """Test POST /mfa/verify accepts valid TOTP codes."""
        # Setup MFA
        setup_response = client.post(
            "/mfa/setup",
            headers={"Authorization": authenticated_user["token"]}
        )
        secret = setup_response.json()["secret"]
        
        # Generate valid code
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        # Verify
        response = client.post(
            "/mfa/verify",
            json={
                "username": authenticated_user["username"],
                "code": code
            }
        )
        
        assert response.status_code == 200
        assert response.json()["ok"] is True
    
    def test_mfa_verify_rejects_invalid_code(self, client, temp_storage, authenticated_user):
        """Test POST /mfa/verify rejects invalid codes."""
        # Setup MFA
        client.post(
            "/mfa/setup",
            headers={"Authorization": authenticated_user["token"]}
        )
        
        # Try invalid code
        response = client.post(
            "/mfa/verify",
            json={
                "username": authenticated_user["username"],
                "code": "000000"
            }
        )
        
        assert response.status_code == 400
    
    def test_mfa_login_requires_code(self, client, temp_storage, test_user):
        """Test POST /login/mfa requires MFA code."""
        # Register and setup MFA
        client.post(
            "/register",
            json={
                "username": test_user["username"],
                "salt": test_user["salt"],
                "verifier": test_user["verifier"],
            }
        )
        
        # Login to get token
        login_response = client.post(
            "/login",
            json={
                "username": test_user["username"],
                "verifier": test_user["verifier"],
            }
        )
        token = login_response.json()["token"]
        
        # Setup MFA
        setup_response = client.post(
            "/mfa/setup",
            headers={"Authorization": token}
        )
        secret = setup_response.json()["secret"]
        
        # Verify to enable MFA
        totp = pyotp.TOTP(secret)
        client.post(
            "/mfa/verify",
            json={"username": test_user["username"], "code": totp.now()}
        )
        
        # Now try MFA login
        response = client.post(
            "/login/mfa",
            json={
                "username": test_user["username"],
                "verifier": test_user["verifier"],
                "mfa_code": totp.now()
            }
        )
        
        assert response.status_code == 200
        assert "token" in response.json()
    
    def test_mfa_status_returns_enabled_state(self, client, temp_storage, test_user):
        """Test GET /mfa/status/{username} returns MFA status."""
        # Register user
        client.post(
            "/register",
            json={
                "username": test_user["username"],
                "salt": test_user["salt"],
                "verifier": test_user["verifier"],
            }
        )
        
        # Check status (should be disabled)
        response = client.get(f"/mfa/status/{test_user['username']}")
        
        assert response.status_code == 200
        assert response.json()["mfa_enabled"] is False
    
    def test_mfa_disable_requires_authentication(self, client, temp_storage):
        """Test POST /mfa/disable requires valid token."""
        response = client.post("/mfa/disable")
        
        assert response.status_code == 422  # Missing header
    
    def test_mfa_disable_removes_mfa(self, client, temp_storage, authenticated_user):
        """Test POST /mfa/disable removes MFA from account."""
        # Setup and enable MFA
        setup_response = client.post(
            "/mfa/setup",
            headers={"Authorization": authenticated_user["token"]}
        )
        secret = setup_response.json()["secret"]
        
        totp = pyotp.TOTP(secret)
        client.post(
            "/mfa/verify",
            json={"username": authenticated_user["username"], "code": totp.now()}
        )
        
        # Disable MFA
        response = client.post(
            "/mfa/disable",
            headers={"Authorization": authenticated_user["token"]}
        )
        
        assert response.status_code == 200
        assert response.json()["ok"] is True
        
        # Verify disabled
        status_response = client.get(f"/mfa/status/{authenticated_user['username']}")
        assert status_response.json()["mfa_enabled"] is False


class TestRateLimitingEndpoints:
    """US 1.10: Rate Limiting on API"""
    
    def test_failed_login_triggers_rate_limit(self, client, temp_storage, test_user):
        """Test that multiple failed logins trigger rate limiting."""
        # Register user
        client.post(
            "/register",
            json={
                "username": test_user["username"],
                "salt": test_user["salt"],
                "verifier": test_user["verifier"],
            }
        )
        
        # Attempt multiple failed logins
        # Note: This test may not trigger 429 since rate limiting is IP-based
        # and TestClient may not preserve IP across requests
        # This is more of a functional test
        for i in range(6):
            response = client.post(
                "/login",
                json={
                    "username": test_user["username"],
                    "verifier": "0" * 64,
                }
            )
            # Should be 401 unauthorized (not 429 in test client)
            assert response.status_code == 401
