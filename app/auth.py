"""Authentication helpers for Argus"""

import secrets
from datetime import datetime, timedelta
from typing import Optional
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Request, Response

# Password hashing configuration
# Using pbkdf2_sha256 instead of bcrypt to avoid version compatibility issues
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Session configuration
SESSION_COOKIE_NAME = "argus_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 days in seconds


def get_secret_key() -> str:
    """Get or generate a secret key for session signing"""
    import os
    secret_file = "./data/.session_secret"

    # Create data directory if it doesn't exist
    os.makedirs("./data", exist_ok=True)

    if os.path.exists(secret_file):
        with open(secret_file, "r") as f:
            return f.read().strip()

    # Generate new secret key
    secret = secrets.token_urlsafe(32)
    with open(secret_file, "w") as f:
        f.write(secret)

    return secret


def get_serializer() -> URLSafeTimedSerializer:
    """Get the session serializer"""
    return URLSafeTimedSerializer(get_secret_key())


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-SHA256"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)


def create_session_token(user_id: int, username: str) -> str:
    """Create a signed session token"""
    serializer = get_serializer()
    data = {
        "user_id": user_id,
        "username": username,
        "created_at": datetime.utcnow().isoformat()
    }
    return serializer.dumps(data)


def verify_session_token(token: str) -> Optional[dict]:
    """Verify and decode a session token"""
    if not token:
        return None

    serializer = get_serializer()
    try:
        data = serializer.loads(token, max_age=SESSION_MAX_AGE)
        return data
    except (BadSignature, SignatureExpired):
        return None


def set_session_cookie(response: Response, user_id: int, username: str, remember: bool = False):
    """Set the session cookie on a response"""
    token = create_session_token(user_id, username)
    max_age = SESSION_MAX_AGE if remember else None  # None = session cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=max_age,
        secure=False  # Set to True in production with HTTPS
    )


def clear_session_cookie(response: Response):
    """Clear the session cookie"""
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        samesite="lax"
    )


def get_current_user(request: Request) -> Optional[dict]:
    """Get the current user from the session cookie"""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    return verify_session_token(token)


# List of paths that don't require authentication
PUBLIC_PATHS = [
    "/login",
    "/setup",
    "/static",
    "/health",
    "/favicon.ico"
]


def requires_auth(path: str) -> bool:
    """Check if a path requires authentication"""
    for public_path in PUBLIC_PATHS:
        if path.startswith(public_path):
            return False
    return True


# API Key Authentication
API_KEY_PREFIX = "argus_"
API_KEY_LENGTH = 32  # Length of the random part


def generate_api_key() -> str:
    """Generate a new API key. Returns the full key (shown once to user)."""
    random_part = secrets.token_urlsafe(API_KEY_LENGTH)
    return f"{API_KEY_PREFIX}{random_part}"


def get_api_key_prefix(key: str) -> str:
    """Get the prefix of an API key for identification."""
    return key[:8] if len(key) >= 8 else key


def hash_api_key(key: str) -> str:
    """Hash an API key for storage. Uses SHA-256 for fast lookups."""
    import hashlib
    return hashlib.sha256(key.encode()).hexdigest()


def verify_api_key(plain_key: str, hashed_key: str) -> bool:
    """Verify an API key against its hash."""
    return hash_api_key(plain_key) == hashed_key


def get_api_key_from_request(request: Request) -> Optional[str]:
    """Extract API key from request headers.

    Supports:
    - X-API-Key header
    - Authorization: Bearer <key>
    """
    # Check X-API-Key header
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key

    # Check Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:]  # Remove "Bearer " prefix

    return None
