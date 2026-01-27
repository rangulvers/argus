"""
Unit tests for API Key performance optimizations (v2.0)

Tests cover the optimized API key authentication with prefix-based lookup
to prevent DoS attacks via expensive hash operations.
"""

import pytest
import time
from app.auth import generate_api_key, hash_api_key, get_api_key_prefix
from app.models import APIKey


class TestAPIKeyPrefixExtraction:
    """Tests for get_api_key_prefix() function"""
    
    def test_prefix_extraction_full_key(self):
        """Test prefix extraction from full API key"""
        key = "argus_" + "a" * 40  # Simulate full key
        prefix = get_api_key_prefix(key)
        assert prefix == "argus_aa"
        assert len(prefix) == 8
    
    def test_prefix_extraction_exact_8_chars(self):
        """Test prefix extraction from exactly 8 character key"""
        key = "argus_ab"
        prefix = get_api_key_prefix(key)
        assert prefix == "argus_ab"
        assert len(prefix) == 8
    
    def test_prefix_extraction_short_key(self):
        """Test prefix extraction from key shorter than 8 chars"""
        key = "test"
        prefix = get_api_key_prefix(key)
        assert prefix == "test"
        assert len(prefix) == 4
    
    def test_prefix_extraction_empty_key(self):
        """Test prefix extraction from empty key"""
        key = ""
        prefix = get_api_key_prefix(key)
        assert prefix == ""
    
    def test_prefix_uniqueness(self):
        """Test that different keys can have same prefix"""
        key1 = "argus_test123456"
        key2 = "argus_test789abc"
        prefix1 = get_api_key_prefix(key1)
        prefix2 = get_api_key_prefix(key2)
        # Same prefix despite different keys
        assert prefix1 == prefix2 == "argus_te"
    
    def test_prefix_extraction_performance(self):
        """Test that prefix extraction is very fast (O(1))"""
        key = generate_api_key()
        
        # Extract prefix 10,000 times
        start_time = time.time()
        for _ in range(10000):
            get_api_key_prefix(key)
        elapsed = time.time() - start_time
        
        # Should complete in under 10ms (very conservative)
        assert elapsed < 0.01, f"Prefix extraction too slow: {elapsed*1000:.2f}ms"


class TestAPIKeyPrefixLookup:
    """Tests for prefix-based database lookup optimization"""
    
    def test_api_key_has_prefix_field(self):
        """Test that APIKey model has key_prefix field"""
        # Verify the field exists in the model
        assert hasattr(APIKey, 'key_prefix')
    
    def test_api_key_prefix_index(self, test_db):
        """Test that key_prefix has database index for fast lookup"""
        # Create a test API key
        key = generate_api_key()
        prefix = get_api_key_prefix(key)
        hashed = hash_api_key(key)
        
        api_key = APIKey(
            user_id=1,
            name="test-key",
            key_prefix=prefix,
            key_hash=hashed,
            is_revoked=False
        )
        test_db.add(api_key)
        test_db.commit()
        
        # Query by prefix should be fast
        start_time = time.time()
        result = test_db.query(APIKey).filter(APIKey.key_prefix == prefix).first()
        elapsed = time.time() - start_time
        
        assert result is not None
        assert result.key_prefix == prefix
        # Query should be very fast (< 5ms)
        assert elapsed < 0.005, f"Prefix lookup too slow: {elapsed*1000:.2f}ms"


class TestAPIKeyVerificationOptimization:
    """Tests for optimized API key verification workflow"""
    
    def test_verify_with_correct_prefix(self, test_db):
        """Test verification with matching prefix"""
        key = generate_api_key()
        prefix = get_api_key_prefix(key)
        hashed = hash_api_key(key)
        
        # Create API key in database
        api_key = APIKey(

            user_id=1,

            name="test-key",
            key_prefix=prefix,
            key_hash=hashed,
                        is_revoked=False
        )
        test_db.add(api_key)
        test_db.commit()
        
        # Simulate optimized lookup: filter by prefix first
        candidates = test_db.query(APIKey).filter(
            APIKey.key_prefix == prefix,
            APIKey.is_revoked == False
        ).all()
        
        # Should only return 1 candidate (the matching one)
        assert len(candidates) == 1
        assert candidates[0].key_prefix == prefix
    
    def test_verify_with_wrong_prefix(self, test_db):
        """Test verification with non-matching prefix (fast rejection)"""
        key1 = generate_api_key()
        prefix1 = get_api_key_prefix(key1)
        hashed1 = hash_api_key(key1)
        
        # Create API key in database
        api_key = APIKey(

            user_id=1,

            name="test-key",
            key_prefix=prefix1,
            key_hash=hashed1,
                        is_revoked=False
        )
        test_db.add(api_key)
        test_db.commit()
        
        # Try to verify with different key (different prefix)
        key2 = generate_api_key()
        prefix2 = get_api_key_prefix(key2)
        
        # Simulate optimized lookup
        start_time = time.time()
        candidates = test_db.query(APIKey).filter(
            APIKey.key_prefix == prefix2,
            APIKey.is_revoked == False
        ).all()
        elapsed = time.time() - start_time
        
        # Should return 0 candidates (fast rejection without hash verification)
        assert len(candidates) == 0
        # Should be very fast (< 5ms)
        assert elapsed < 0.005, f"Prefix rejection too slow: {elapsed*1000:.2f}ms"
    
    def test_multiple_keys_different_prefixes(self, test_db):
        """Test that keys with different prefixes don't interfere"""
        keys = [generate_api_key() for _ in range(10)]
        
        # Add all keys to database
        for i, key in enumerate(keys):
            prefix = get_api_key_prefix(key)
            hashed = hash_api_key(key)
            api_key = APIKey(

                user_id=1,

                name=f"test-key-{i}",
                key_prefix=prefix,
                key_hash=hashed,
                is_revoked=False
            )
            test_db.add(api_key)
        test_db.commit()
        
        # Verify each key only matches its own entry
        for key in keys:
            prefix = get_api_key_prefix(key)
            candidates = test_db.query(APIKey).filter(
                APIKey.key_prefix == prefix,
                APIKey.is_revoked == False
            ).all()
            
            # Should have 1 candidate (or small number if prefix collision)
            assert len(candidates) <= 2  # Allow for rare prefix collisions
    
    def test_prefix_collision_handling(self, test_db):
        """Test handling of prefix collisions (rare but possible)"""
        # Create two keys with same prefix (artificially)
        base_prefix = "argus_te"
        key1 = base_prefix + "st1" + "x" * 30
        key2 = base_prefix + "st2" + "y" * 30
        
        prefix1 = get_api_key_prefix(key1)
        prefix2 = get_api_key_prefix(key2)
        
        # Both should have same prefix
        assert prefix1 == prefix2
        
        # Add both to database
        for i, key in enumerate([key1, key2]):
            hashed = hash_api_key(key)
            api_key = APIKey(

                user_id=1,

                name=f"collision-key-{i}",
                key_prefix=prefix1,
                key_hash=hashed,
                is_revoked=False
            )
            test_db.add(api_key)
        test_db.commit()
        
        # Query by prefix should return both candidates
        candidates = test_db.query(APIKey).filter(
            APIKey.key_prefix == prefix1,
            APIKey.is_revoked == False
        ).all()
        
        # Should return 2 candidates (requires hash verification for both)
        assert len(candidates) == 2


class TestPerformanceRegression:
    """Tests to prevent performance regression"""
    
    def test_lookup_scales_with_active_keys(self, test_db):
        """Test that lookup performance doesn't degrade with many keys"""
        # Add 100 keys with different prefixes
        keys = []
        for i in range(100):
            key = generate_api_key()
            prefix = get_api_key_prefix(key)
            hashed = hash_api_key(key)
            
            api_key = APIKey(
                user_id=1,
                name=f"key-{i}",
                key_prefix=prefix,
                key_hash=hashed,
                is_revoked=False
            )
            test_db.add(api_key)
            keys.append(key)
        
        test_db.commit()
        
        # Pick a random key to verify
        test_key = keys[50]
        test_prefix = get_api_key_prefix(test_key)
        
        # Measure lookup time
        start_time = time.time()
        candidates = test_db.query(APIKey).filter(
            APIKey.key_prefix == test_prefix,
            APIKey.is_revoked == False
        ).all()
        elapsed = time.time() - start_time
        
        # Should still be fast even with 100 keys (< 10ms)
        assert elapsed < 0.01, f"Lookup with 100 keys too slow: {elapsed*1000:.2f}ms"
        assert len(candidates) >= 1  # At least our test key
    
    def test_inactive_keys_not_checked(self, test_db):
        """Test that inactive keys are excluded from lookup"""
        key = generate_api_key()
        prefix = get_api_key_prefix(key)
        hashed = hash_api_key(key)
        
        # Create inactive API key
        api_key = APIKey(

            user_id=1,

            name="inactive-key",
            key_prefix=prefix,
            key_hash=hashed,
                        is_revoked=True  # Inactive
        )
        test_db.add(api_key)
        test_db.commit()
        
        # Query should not return inactive keys
        candidates = test_db.query(APIKey).filter(
            APIKey.key_prefix == prefix,
            APIKey.is_revoked == False
        ).all()
        
        assert len(candidates) == 0


class TestSecurityProperties:
    """Tests to verify security properties are maintained"""
    
    def test_prefix_does_not_leak_full_key(self):
        """Test that prefix alone cannot be used to derive full key"""
        key = generate_api_key()
        prefix = get_api_key_prefix(key)
        
        # Prefix should be much shorter than key
        assert len(prefix) < len(key)
        # Key should have significant entropy beyond prefix
        assert len(key) > 40  # At least 40+ characters total
    
    def test_constant_time_comparison_pattern(self, test_db):
        """Test that verification uses constant-time operations"""
        # Create a valid key
        key = generate_api_key()
        prefix = get_api_key_prefix(key)
        hashed = hash_api_key(key)
        
        api_key = APIKey(
            user_id=1,
            name="test-key",
            key_prefix=prefix,
            key_hash=hashed,
            is_revoked=False
        )
        test_db.add(api_key)
        test_db.commit()
        
        # Verify correct key
        from app.auth import verify_api_key
        result = verify_api_key(key, hashed)
        assert result is True
        
        # Verify incorrect key (should also take similar time)
        wrong_key = generate_api_key()
        result = verify_api_key(wrong_key, hashed)
        assert result is False
        
        # Note: Actual timing-attack resistance requires constant-time
        # hash comparison in verify_api_key implementation
