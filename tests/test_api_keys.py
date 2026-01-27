"""Tests for API Key authentication"""

import pytest
from app.auth import (
    generate_api_key,
    hash_api_key,
    verify_api_key,
    get_api_key_prefix,
    get_api_key_from_request,
    API_KEY_PREFIX,
)


class TestAPIKeyGeneration:
    """Tests for API key generation"""

    def test_generate_api_key_has_prefix(self):
        """Test generated key has correct prefix"""
        key = generate_api_key()
        assert key.startswith(API_KEY_PREFIX)

    def test_generate_api_key_length(self):
        """Test generated key has reasonable length"""
        key = generate_api_key()
        # Should be prefix (6 chars) + random part (43 chars for 32 bytes base64)
        assert len(key) > 40

    def test_generate_api_key_unique(self):
        """Test each generated key is unique"""
        key1 = generate_api_key()
        key2 = generate_api_key()
        assert key1 != key2

    def test_generate_api_key_format(self):
        """Test key is URL-safe"""
        key = generate_api_key()
        # URL-safe characters only
        import re
        assert re.match(r'^[a-zA-Z0-9_-]+$', key)


class TestAPIKeyHashing:
    """Tests for API key hashing"""

    def test_hash_api_key_returns_string(self):
        """Test hash returns string"""
        key = generate_api_key()
        hashed = hash_api_key(key)
        assert isinstance(hashed, str)

    def test_hash_api_key_deterministic(self):
        """Test same key can be verified (passlib uses random salts)"""
        key = generate_api_key()
        hash1 = hash_api_key(key)
        hash2 = hash_api_key(key)
        # Hashes will differ due to random salts, but both should verify
        assert verify_api_key(key, hash1)
        assert verify_api_key(key, hash2)

    def test_hash_api_key_different_keys(self):
        """Test different keys produce different hashes"""
        key1 = generate_api_key()
        key2 = generate_api_key()
        hash1 = hash_api_key(key1)
        hash2 = hash_api_key(key2)
        assert hash1 != hash2

    def test_hash_length(self):
        """Test hash is in passlib format (not raw SHA-256)"""
        key = generate_api_key()
        hashed = hash_api_key(key)
        # Passlib pbkdf2_sha256 format: $pbkdf2-sha256$rounds$salt$hash
        assert hashed.startswith('$pbkdf2-sha256$')
        assert len(hashed) > 64  # Full passlib format is longer than raw hash


class TestAPIKeyVerification:
    """Tests for API key verification"""

    def test_verify_correct_key(self):
        """Test verifying correct key"""
        key = generate_api_key()
        hashed = hash_api_key(key)
        assert verify_api_key(key, hashed) is True

    def test_verify_incorrect_key(self):
        """Test verifying incorrect key"""
        key1 = generate_api_key()
        key2 = generate_api_key()
        hashed = hash_api_key(key1)
        assert verify_api_key(key2, hashed) is False

    def test_verify_empty_key(self):
        """Test verifying empty key"""
        key = generate_api_key()
        hashed = hash_api_key(key)
        assert verify_api_key("", hashed) is False


class TestAPIKeyPrefix:
    """Tests for API key prefix extraction"""

    def test_get_prefix_full_key(self):
        """Test getting prefix from full key"""
        key = generate_api_key()
        prefix = get_api_key_prefix(key)
        assert len(prefix) == 8
        assert key.startswith(prefix)

    def test_get_prefix_short_key(self):
        """Test getting prefix from short key"""
        key = "abc"
        prefix = get_api_key_prefix(key)
        assert prefix == "abc"


class TestAPIKeyFromRequest:
    """Tests for extracting API key from request"""

    def test_get_key_from_x_api_key_header(self):
        """Test getting key from X-API-Key header"""
        class MockRequest:
            def __init__(self):
                self.headers = {"X-API-Key": "test_key_123"}

        request = MockRequest()
        key = get_api_key_from_request(request)
        assert key == "test_key_123"

    def test_get_key_from_bearer_header(self):
        """Test getting key from Authorization Bearer header"""
        class MockRequest:
            def __init__(self):
                self.headers = {"Authorization": "Bearer test_key_456"}

        request = MockRequest()
        key = get_api_key_from_request(request)
        assert key == "test_key_456"

    def test_no_key_in_headers(self):
        """Test when no API key in headers"""
        class MockRequest:
            def __init__(self):
                self.headers = {}

        request = MockRequest()
        key = get_api_key_from_request(request)
        assert key is None

    def test_x_api_key_takes_precedence(self):
        """Test X-API-Key takes precedence over Bearer"""
        class MockRequest:
            def __init__(self):
                self.headers = {
                    "X-API-Key": "key_from_x_api",
                    "Authorization": "Bearer key_from_bearer"
                }

        request = MockRequest()
        key = get_api_key_from_request(request)
        assert key == "key_from_x_api"

    def test_invalid_bearer_format(self):
        """Test with invalid Bearer format"""
        class MockRequest:
            def __init__(self):
                self.headers = {"Authorization": "Basic abc123"}

        request = MockRequest()
        key = get_api_key_from_request(request)
        assert key is None
