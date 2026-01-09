"""Tests for version module"""

import pytest
from app.version import get_version, get_build_info, DEFAULT_VERSION


class TestGetVersion:
    """Tests for get_version function"""

    def test_returns_string(self):
        """Test get_version returns a string"""
        version = get_version()
        assert isinstance(version, str)

    def test_returns_non_empty(self):
        """Test get_version returns non-empty string"""
        version = get_version()
        assert len(version) > 0

    def test_default_version_fallback(self):
        """Test DEFAULT_VERSION is defined"""
        assert DEFAULT_VERSION is not None
        assert isinstance(DEFAULT_VERSION, str)


class TestGetBuildInfo:
    """Tests for get_build_info function"""

    def test_returns_dict(self):
        """Test get_build_info returns a dictionary"""
        info = get_build_info()
        assert isinstance(info, dict)

    def test_contains_version(self):
        """Test build info contains version"""
        info = get_build_info()
        assert 'version' in info

    def test_version_matches(self):
        """Test build info version matches get_version"""
        info = get_build_info()
        version = get_version()
        assert info['version'] == version

    def test_optional_fields(self):
        """Test optional fields are present or None"""
        info = get_build_info()

        # These fields may or may not be present
        optional_fields = ['build_date', 'commit', 'branch']
        for field in optional_fields:
            # Just ensure no error when accessed
            _ = info.get(field)


class TestVersionCaching:
    """Tests for version caching behavior"""

    def test_version_cached(self):
        """Test version is cached (returns same value)"""
        version1 = get_version()
        version2 = get_version()
        assert version1 == version2

    def test_build_info_cached(self):
        """Test build info is cached"""
        info1 = get_build_info()
        info2 = get_build_info()
        assert info1 == info2
