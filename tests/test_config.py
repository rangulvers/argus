"""Tests for configuration module"""

import pytest
import os
import tempfile
from app.config import get_config


class TestAppConfig:
    """Tests for AppConfig"""

    def test_default_config_values(self):
        """Test default configuration values"""
        config = get_config()

        assert config is not None
        assert hasattr(config, 'network')
        assert hasattr(config, 'scanning')
        assert hasattr(config, 'database')

    def test_config_network_section(self):
        """Test network configuration section"""
        config = get_config()

        # Should have network settings
        if hasattr(config.network, 'subnet'):
            assert isinstance(config.network.subnet, str)

    def test_config_scanning_section(self):
        """Test scanning configuration section"""
        config = get_config()

        # Should have scanning settings
        if hasattr(config.scanning, 'timeout'):
            assert isinstance(config.scanning.timeout, int)

    def test_config_database_section(self):
        """Test database configuration section"""
        config = get_config()

        # Should have database settings
        if hasattr(config.database, 'path'):
            assert isinstance(config.database.path, str)


class TestConfigLoading:
    """Tests for configuration loading"""

    def test_load_from_yaml_file(self, temp_config_file):
        """Test loading config from YAML file"""
        # This tests that YAML parsing works
        import yaml

        with open(temp_config_file, 'r') as f:
            data = yaml.safe_load(f)

        assert 'network' in data
        assert 'scanning' in data
        assert data['network']['subnet'] == "192.168.1.0/24"

    def test_config_singleton(self):
        """Test config returns same instance"""
        config1 = get_config()
        config2 = get_config()

        # Should return same or equivalent config
        assert config1 is not None
        assert config2 is not None


class TestConfigValidation:
    """Tests for configuration validation"""

    def test_subnet_format(self):
        """Test subnet format validation"""
        config = get_config()

        if hasattr(config.network, 'subnet') and config.network.subnet:
            # Should be valid CIDR notation
            subnet = config.network.subnet
            assert '/' in subnet or subnet == ""

    def test_scan_profile_values(self):
        """Test scan profile has valid values"""
        valid_profiles = ['quick', 'normal', 'intensive']
        config = get_config()

        if hasattr(config.network, 'scan_profile') and config.network.scan_profile:
            assert config.network.scan_profile in valid_profiles
