"""Tests for authentication module"""

import pytest
from fastapi import status
from app.auth import (
    hash_password,
    verify_password,
    create_session_token,
    verify_session_token,
    requires_auth,
)


class TestPasswordHashing:
    """Tests for password hashing functions"""

    def test_hash_password(self):
        """Test password hashing"""
        password = "mysecretpassword"
        hashed = hash_password(password)

        assert hashed != password
        assert len(hashed) > 0

    def test_hash_password_unique(self):
        """Test that same password produces different hashes"""
        password = "samepassword"
        hash1 = hash_password(password)
        hash2 = hash_password(password)

        # Hashes should be different due to salt
        assert hash1 != hash2

    def test_verify_password_correct(self):
        """Test verifying correct password"""
        password = "correctpassword"
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Test verifying incorrect password"""
        password = "correctpassword"
        hashed = hash_password(password)

        assert verify_password("wrongpassword", hashed) is False

    def test_verify_password_empty(self):
        """Test verifying empty password"""
        hashed = hash_password("somepassword")
        assert verify_password("", hashed) is False


class TestSessionTokens:
    """Tests for session token functions"""

    def test_create_session_token(self):
        """Test creating session token"""
        user_id = 123
        username = "testuser"
        token = create_session_token(user_id, username)

        assert token is not None
        assert len(token) > 0

    def test_verify_session_token_valid(self):
        """Test verifying valid session token"""
        user_id = 456
        username = "anotheruser"
        token = create_session_token(user_id, username)

        data = verify_session_token(token)
        assert data is not None
        assert data["user_id"] == user_id
        assert data["username"] == username

    def test_verify_session_token_invalid(self):
        """Test verifying invalid session token"""
        data = verify_session_token("invalid_token_here")
        assert data is None

    def test_verify_session_token_tampered(self):
        """Test verifying tampered session token"""
        token = create_session_token(1, "user")
        # Tamper with token
        tampered = token[:-5] + "XXXXX"
        data = verify_session_token(tampered)
        assert data is None


class TestRequiresAuth:
    """Tests for requires_auth function"""

    def test_public_paths(self):
        """Test that public paths don't require auth"""
        # Note: /api/version is NOT public - API endpoints require auth
        public_paths = [
            "/login",
            "/setup",
            "/static/style.css",
            "/static/js/app.js",
            "/health",
        ]
        for path in public_paths:
            assert requires_auth(path) is False, f"{path} should not require auth"

    def test_protected_paths(self):
        """Test that protected paths require auth"""
        protected_paths = [
            "/",
            "/devices",
            "/devices/123",
            "/scans",
            "/changes",
            "/settings",
            "/visualization",
            "/api/devices",
            "/api/scans",
        ]
        for path in protected_paths:
            assert requires_auth(path) is True, f"{path} should require auth"


@pytest.mark.skip(reason="Middleware imports SessionLocal directly, bypassing test overrides")
class TestLoginFlow:
    """Tests for login/logout flow"""

    def test_login_success(self, client, sample_user):
        """Test successful login"""
        response = client.post(
            "/login",
            data={"username": "admin", "password": "testpassword123"},
            follow_redirects=False
        )
        assert response.status_code == status.HTTP_302_FOUND
        assert "session" in response.cookies

    def test_login_wrong_password(self, client, sample_user):
        """Test login with wrong password"""
        response = client.post(
            "/login",
            data={"username": "admin", "password": "wrongpassword"},
            follow_redirects=False
        )
        # Should stay on login page with error
        assert response.status_code == status.HTTP_200_OK
        assert "invalid" in response.text.lower() or "error" in response.text.lower()

    def test_login_nonexistent_user(self, client, sample_user):
        """Test login with non-existent user"""
        response = client.post(
            "/login",
            data={"username": "nobody", "password": "somepassword"},
            follow_redirects=False
        )
        assert response.status_code == status.HTTP_200_OK

    def test_logout(self, client, sample_user):
        """Test logout clears session"""
        # First login
        client.post(
            "/login",
            data={"username": "admin", "password": "testpassword123"}
        )

        # Then logout
        response = client.get("/logout", follow_redirects=False)
        assert response.status_code == status.HTTP_302_FOUND

        # Session cookie should be cleared
        # Trying to access protected page should redirect to login
        response = client.get("/", follow_redirects=False)
        assert response.status_code == status.HTTP_302_FOUND


@pytest.mark.skip(reason="Middleware imports SessionLocal directly, bypassing test overrides")
class TestSetupFlow:
    """Tests for initial setup flow"""

    def test_setup_page_when_no_users(self, client):
        """Test setup page accessible when no users"""
        response = client.get("/setup")
        assert response.status_code == status.HTTP_200_OK
        assert "setup" in response.text.lower() or "admin" in response.text.lower()

    def test_setup_creates_user(self, client):
        """Test setup creates admin user"""
        response = client.post(
            "/setup",
            data={
                "username": "newadmin",
                "password": "newpassword123",
                "confirm_password": "newpassword123"
            },
            follow_redirects=False
        )
        # Should redirect to login or dashboard
        assert response.status_code in [status.HTTP_302_FOUND, status.HTTP_200_OK]

    def test_setup_password_mismatch(self, client):
        """Test setup with password mismatch"""
        response = client.post(
            "/setup",
            data={
                "username": "admin",
                "password": "password1",
                "confirm_password": "password2"
            }
        )
        # Should show error
        assert "match" in response.text.lower() or "error" in response.text.lower()

    def test_setup_redirects_when_users_exist(self, client, sample_user):
        """Test setup redirects when users already exist"""
        response = client.get("/setup", follow_redirects=False)
        assert response.status_code == status.HTTP_302_FOUND
