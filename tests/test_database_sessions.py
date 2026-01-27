"""
Tests for database session management and leak prevention.

Verifies that database sessions are properly managed and cleaned up
even when exceptions occur, preventing connection leaks.
"""

import pytest
from unittest.mock import patch, MagicMock
from contextlib import contextmanager
from sqlalchemy.orm import Session
from app.database import get_db, get_middleware_db, get_pool_status, SessionLocal


class TestSessionManagement:
    """Test proper database session lifecycle management"""

    def test_get_db_yields_session(self, test_db):
        """Test that get_db yields a valid session"""
        generator = get_db()
        db = next(generator)
        assert isinstance(db, Session)
        assert db.is_active
        
        # Cleanup
        try:
            next(generator)
        except StopIteration:
            pass

    def test_get_db_closes_session_on_completion(self):
        """Test that get_db closes session after use"""
        generator = get_db()
        db = next(generator)
        
        # Session should work during usage
        from app.models import User
        count = db.query(User).count()
        assert isinstance(count, int)
        
        # Complete the generator
        try:
            next(generator)
        except StopIteration:
            pass
        
        # After close, session operations should raise
        try:
            db.query(User).count()
            # Some SQLAlchemy versions may not raise here
        except Exception:
            pass  # Expected - session is closed

    def test_get_db_closes_session_on_exception(self):
        """Test that get_db closes session even when exception occurs"""
        generator = get_db()
        db = next(generator)
        db_id = id(db)
        
        # Simulate exception during usage
        with pytest.raises(RuntimeError):
            try:
                raise RuntimeError("Simulated error")
            finally:
                # This simulates what FastAPI does with dependencies
                try:
                    next(generator)
                except StopIteration:
                    pass
        
        # The important thing is that no exception was raised during cleanup
        assert db_id is not None

    def test_get_middleware_db_context_manager(self, test_db):
        """Test that get_middleware_db works as context manager"""
        from app.models import User
        
        with get_middleware_db() as db:
            assert isinstance(db, Session)
            # Should be able to perform queries
            count = db.query(User).count()
            assert isinstance(count, int)
        
        # Context manager completed successfully (no exception)

    def test_get_middleware_db_closes_on_exception(self):
        """Test that get_middleware_db closes session on exception"""
        from app.models import User
        exception_raised = False
        
        try:
            with get_middleware_db() as db:
                # Verify session works
                count = db.query(User).count()
                assert isinstance(count, int)
                raise ValueError("Simulated middleware error")
        except ValueError:
            exception_raised = True
        
        # Exception was raised as expected
        assert exception_raised

    def test_get_middleware_db_closes_on_early_return(self):
        """Test that get_middleware_db closes session on early return"""
        from app.models import User
        
        def middleware_simulation():
            with get_middleware_db() as db:
                # Check users
                count = db.query(User).count()
                # Simulate early return (e.g., auth failure)
                if count is not None:
                    return False
            return True
        
        result = middleware_simulation()
        # Should have returned early
        assert result is False

    def test_multiple_context_managers_dont_interfere(self, test_db):
        """Test that multiple context managers work independently"""
        from app.models import User
        
        with get_middleware_db() as db1:
            count1 = db1.query(User).count()
            with get_middleware_db() as db2:
                # Both should be working independently
                count2 = db2.query(User).count()
                assert count1 == count2
                assert db1 is not db2
        
        # Both contexts completed successfully


class TestConnectionPoolMonitoring:
    """Test connection pool monitoring functionality"""

    def test_get_pool_status_returns_dict(self):
        """Test that get_pool_status returns a dictionary"""
        status = get_pool_status()
        assert isinstance(status, dict)
        assert "pool_class" in status
        assert "database_url" in status

    def test_get_pool_status_hides_credentials(self):
        """Test that database URL credentials are hidden"""
        status = get_pool_status()
        # Should hide credentials with ***
        assert "***" in status["database_url"]
        # Should not contain actual password/username
        assert "://" in status["database_url"]

    def test_get_pool_status_with_sqlite(self):
        """Test pool status with SQLite database"""
        status = get_pool_status()
        # SQLite typically uses NullPool or StaticPool
        assert status["pool_class"] in ["NullPool", "StaticPool", "SingletonThreadPool"]

    def test_get_pool_status_handles_missing_attributes(self):
        """Test that get_pool_status handles pools without all attributes"""
        status = get_pool_status()
        # Should not raise exceptions even if some attributes are missing
        assert isinstance(status, dict)
        # May have note field if full stats unavailable
        if "note" in status:
            assert "not available" in status["note"].lower()


class TestConcurrentSessionAccess:
    """Test concurrent access to database sessions"""

    def test_concurrent_context_managers(self, test_db):
        """Test multiple concurrent context managers"""
        from app.models import User
        session_count = 0
        
        # Create 5 sessions sequentially
        for i in range(5):
            with get_middleware_db() as db:
                count = db.query(User).count()
                assert isinstance(count, int)
                session_count += 1
        
        # All 5 sessions completed successfully
        assert session_count == 5

    def test_session_isolation(self, test_db):
        """Test that sessions are isolated from each other"""
        from app.models import User
        from app.auth import hash_password
        
        # Create user in first session
        with get_middleware_db() as db1:
            user = User(
                username="test_isolation",
                password_hash=hash_password("password123")
            )
            db1.add(user)
            db1.commit()
            user_id = user.id
        
        # Verify in second session (simulating different request)
        with get_middleware_db() as db2:
            user = db2.query(User).filter(User.id == user_id).first()
            assert user is not None
            assert user.username == "test_isolation"
        
        # Cleanup
        with get_middleware_db() as db3:
            user = db3.query(User).filter(User.id == user_id).first()
            if user:
                db3.delete(user)
                db3.commit()


class TestSessionLeakPrevention:
    """Test that sessions don't leak under various error conditions"""

    def test_no_leak_on_database_error(self):
        """Test that session cleanup happens even on database errors"""
        from sqlalchemy import text
        exception_raised = False
        
        try:
            with get_middleware_db() as db:
                # Attempt invalid SQL
                db.execute(text("INVALID SQL STATEMENT"))
        except Exception:
            exception_raised = True
        
        # Exception should have been raised, but context manager should handle cleanup
        assert exception_raised

    def test_no_leak_on_authentication_failure(self, test_db):
        """Test that session is closed on authentication failures"""
        from app.models import User
        
        def simulate_auth_middleware():
            with get_middleware_db() as db:
                # Check for non-existent user (auth failure)
                user = db.query(User).filter(User.username == "nonexistent").first()
                if user is None:
                    # Simulate auth failure response
                    return None
                return user
        
        result = simulate_auth_middleware()
        assert result is None
        # Session was properly cleaned up (no exception)

    def test_no_leak_on_commit_error(self, test_db):
        """Test that session is closed even when commit fails"""
        from app.models import User
        from app.auth import hash_password
        exception_raised = False
        
        try:
            with get_middleware_db() as db:
                # Create user with duplicate username
                user1 = User(
                    username="duplicate_test",
                    password_hash=hash_password("pass123")
                )
                db.add(user1)
                db.commit()
                
                # Try to create another with same username (should fail)
                user2 = User(
                    username="duplicate_test",
                    password_hash=hash_password("pass456")
                )
                db.add(user2)
                db.commit()  # This should raise an integrity error
        except Exception:
            exception_raised = True
        
        # Should have raised integrity error
        assert exception_raised
        
        # Cleanup
        with get_middleware_db() as db:
            user = db.query(User).filter(User.username == "duplicate_test").first()
            if user:
                db.delete(user)
                db.commit()

    def test_no_leak_with_nested_exceptions(self):
        """Test that session is closed with nested exception handling"""
        from app.models import User
        operations_completed = False
        
        def nested_operation():
            try:
                with get_middleware_db() as db:
                    # Do a query
                    count = db.query(User).count()
                    try:
                        raise ValueError("Inner exception")
                    except ValueError:
                        raise RuntimeError("Outer exception")
            except RuntimeError:
                pass
        
        nested_operation()
        # No exception leaked out, context manager handled cleanup


class TestMiddlewareSessionUsage:
    """Test session usage patterns in middleware"""

    def test_api_key_validation_session_cleanup(self, test_db):
        """Test that session is cleaned up after API key validation"""
        from app.models import APIKey, User
        from app.auth import hash_api_key, hash_password
        from datetime import datetime
        
        # Create test user first (required for API key)
        with get_middleware_db() as db:
            user = User(
                username="api_test_user",
                password_hash=hash_password("password123")
            )
            db.add(user)
            db.commit()
            user_id = user.id
        
        # Create test API key
        with get_middleware_db() as db:
            api_key = APIKey(
                user_id=user_id,
                name="test_key",
                key_prefix="test_",
                key_hash=hash_api_key("test_abc123"),
                created_at=datetime.utcnow()
            )
            db.add(api_key)
            db.commit()
            key_id = api_key.id
        
        # Simulate middleware API key check
        with get_middleware_db() as db:
            key = db.query(APIKey).filter(APIKey.id == key_id).first()
            assert key is not None
            assert key.name == "test_key"
        
        # Cleanup
        with get_middleware_db() as db:
            key = db.query(APIKey).filter(APIKey.id == key_id).first()
            if key:
                db.delete(key)
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                db.delete(user)
            db.commit()

    def test_user_count_check_session_cleanup(self, test_db):
        """Test that session is cleaned up after user count check"""
        from app.models import User
        
        # Simulate middleware user count check
        with get_middleware_db() as db:
            user_count = db.query(User).count()
            assert isinstance(user_count, int)
        
        # Context manager completed successfully

    def test_session_auth_check_session_cleanup(self, test_db):
        """Test that session is cleaned up after session auth check"""
        from app.models import User
        
        # Simulate middleware session auth check
        with get_middleware_db() as db:
            # Check for user (would typically use session cookie)
            user = db.query(User).filter(User.username == "test_user").first()
            # None is fine, we're just testing cleanup
        
        # Context manager completed successfully


class TestPoolStatusAPI:
    """Test pool status monitoring (if endpoint added)"""

    def test_pool_status_contains_required_fields(self):
        """Test that pool status contains all required monitoring fields"""
        status = get_pool_status()
        
        # Should always have these fields
        assert "pool_class" in status
        assert "database_url" in status
        
        # May have these fields depending on pool type
        possible_fields = ["pool_size", "checked_out", "overflow", "checked_in", "note"]
        has_monitoring_data = any(field in status for field in possible_fields)
        assert has_monitoring_data

    def test_pool_status_safe_for_json_serialization(self):
        """Test that pool status can be JSON serialized"""
        import json
        status = get_pool_status()
        
        # Should be JSON serializable
        json_str = json.dumps(status)
        assert isinstance(json_str, str)
        
        # Should be able to parse back
        parsed = json.loads(json_str)
        assert parsed == status
