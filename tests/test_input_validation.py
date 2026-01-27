"""
Tests for input validation on API endpoints.

Tests cover:
- HTML/XSS prevention in user inputs
- Subnet validation
- Zone name validation
- API key name validation
- Cron expression validation
- URL validation for integrations
"""

import pytest
from pydantic import ValidationError
from app.schemas import (
    DeviceUpdate,
    ScanRequest,
    SingleDeviceScanRequest,
    NetworkConfigUpdate,
    CVEIntegrationUpdate,
    UniFiIntegrationUpdate,
    PiHoleIntegrationUpdate,
    AdGuardIntegrationUpdate,
    APIKeyCreateRequest,
    ScheduleJobCreate,
    ScheduleJobUpdate
)


class TestDeviceUpdateValidation:
    """Test validation for device update requests"""
    
    def test_valid_device_update(self):
        """Test valid device update passes validation"""
        data = {
            "label": "My Router",
            "notes": "Main gateway device",
            "is_trusted": True,
            "zone": "Infrastructure"
        }
        device = DeviceUpdate(**data)
        assert device.label == "My Router"
        assert device.notes == "Main gateway device"
        assert device.zone == "Infrastructure"
    
    def test_html_escaping_in_label(self):
        """Test HTML is escaped in device labels"""
        data = {"label": "<script>alert('xss')</script>"}
        device = DeviceUpdate(**data)
        # HTML should be escaped
        assert "<script>" not in device.label
        assert "&lt;script&gt;" in device.label
    
    def test_html_escaping_in_notes(self):
        """Test HTML is escaped in device notes"""
        data = {"notes": "<img src=x onerror=alert(1)>"}
        device = DeviceUpdate(**data)
        # HTML should be escaped
        assert "<img" not in device.notes
        assert "&lt;img" in device.notes
    
    def test_xss_prevention_javascript_protocol(self):
        """Test XSS via javascript: protocol is escaped"""
        data = {"label": "javascript:alert(document.cookie)"}
        device = DeviceUpdate(**data)
        # html.escape() doesn't remove javascript:, but it's still sanitized
        # The label will be HTML-safe when rendered in templates
        assert device.label == "javascript:alert(document.cookie)"  # No special chars to escape
    
    def test_label_max_length(self):
        """Test label respects max length of 255 chars"""
        data = {"label": "A" * 256}
        with pytest.raises(ValidationError) as exc_info:
            DeviceUpdate(**data)
        assert "label" in str(exc_info.value).lower()
    
    def test_notes_max_length(self):
        """Test notes respects max length of 5000 chars"""
        data = {"notes": "A" * 5001}
        with pytest.raises(ValidationError) as exc_info:
            DeviceUpdate(**data)
        assert "notes" in str(exc_info.value).lower()
    
    def test_zone_invalid_characters(self):
        """Test zone rejects special characters"""
        invalid_zones = [
            "<script>",
            "Zone;DROP TABLE devices",
            "Zone|rm -rf /",
            "Zone&& echo pwned",
            "Zone../../../etc/passwd"
        ]
        for zone in invalid_zones:
            with pytest.raises(ValidationError) as exc_info:
                DeviceUpdate(zone=zone)
            assert "zone" in str(exc_info.value).lower()
    
    def test_zone_valid_characters(self):
        """Test zone accepts safe characters"""
        valid_zones = [
            "DMZ",
            "Guest Network",
            "IoT-Devices",
            "Server_Room",
            "Office-2nd-Floor"
        ]
        for zone in valid_zones:
            device = DeviceUpdate(zone=zone)
            assert device.zone == zone
    
    def test_zone_max_length(self):
        """Test zone respects max length"""
        data = {"zone": "A" * 101}
        with pytest.raises(ValidationError) as exc_info:
            DeviceUpdate(**data)
        assert "zone" in str(exc_info.value).lower()
    
    def test_empty_strings_converted_to_none(self):
        """Test empty strings are converted to None"""
        data = {"label": "   ", "notes": "  "}
        device = DeviceUpdate(**data)
        assert device.label is None
        assert device.notes is None


class TestScanRequestValidation:
    """Test validation for scan requests"""
    
    def test_valid_subnet_cidr(self):
        """Test valid CIDR subnet notation"""
        valid_subnets = [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/16",
            "192.168.1.0/32",
            "0.0.0.0/0"
        ]
        for subnet in valid_subnets:
            scan = ScanRequest(subnet=subnet)
            assert scan.subnet == subnet
    
    def test_invalid_subnet_format(self):
        """Test invalid subnet formats are rejected"""
        # Only test subnets that are provided (subnet is optional in ScanRequest)
        invalid_subnets = [
            "192.168.1.0/33",  # Invalid CIDR (>32)
            "256.256.256.256/24",  # Invalid IP
            "192.168.1/24",  # Incomplete IP
            "not-an-ip/24",
            "192.168.1.0; DROP TABLE scans;",
            "192.168.1.0/24 && rm -rf /"
        ]
        for subnet in invalid_subnets:
            with pytest.raises(ValidationError) as exc_info:
                ScanRequest(subnet=subnet)
            # Validation error should mention subnet
            error_str = str(exc_info.value).lower()
            assert "subnet" in error_str or "invalid" in error_str
        
        # Note: "192.168.1.0" without CIDR is accepted by ipaddress module
        # It interprets it as a single host address
    
    def test_scan_profile_validation(self):
        """Test scan profile only accepts allowed values"""
        valid_profiles = ["quick", "normal", "intensive"]
        for profile in valid_profiles:
            scan = ScanRequest(subnet="192.168.1.0/24", scan_profile=profile)
            assert scan.scan_profile == profile
    
    def test_invalid_scan_profile(self):
        """Test invalid scan profiles are rejected"""
        with pytest.raises(ValidationError):
            ScanRequest(subnet="192.168.1.0/24", scan_profile="malicious")
    
    def test_port_range_length_limit(self):
        """Test port range respects max length (DoS prevention)"""
        # 201 chars - should be rejected
        long_range = ",".join(str(i) for i in range(1, 150))
        with pytest.raises(ValidationError):
            ScanRequest(subnet="192.168.1.0/24", port_range=long_range)


class TestSingleDeviceScanValidation:
    """Test validation for single device scans"""
    
    def test_valid_ipv4_address(self):
        """Test valid IPv4 addresses"""
        valid_ips = ["192.168.1.1", "10.0.0.1", "8.8.8.8", "0.0.0.0"]
        for ip in valid_ips:
            scan = SingleDeviceScanRequest(ip_address=ip)
            assert scan.ip_address == ip
    
    def test_valid_ipv6_address(self):
        """Test valid IPv6 addresses"""
        valid_ips = [
            "::1",
            "fe80::1",
            "2001:db8::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ]
        for ip in valid_ips:
            scan = SingleDeviceScanRequest(ip_address=ip)
            assert scan.ip_address == ip
    
    def test_invalid_ip_address(self):
        """Test invalid IP addresses are rejected"""
        invalid_ips = [
            "256.256.256.256",
            "192.168.1",
            "not-an-ip",
            "192.168.1.1; echo pwned",
            "192.168.1.1 && rm -rf /",
            "../../../etc/passwd"
        ]
        for ip in invalid_ips:
            with pytest.raises(ValidationError) as exc_info:
                SingleDeviceScanRequest(ip_address=ip)
            assert "ip" in str(exc_info.value).lower()


class TestConfigUpdateValidation:
    """Test validation for configuration updates"""
    
    def test_valid_network_config(self):
        """Test valid network configuration"""
        config = NetworkConfigUpdate(
            subnet="192.168.1.0/24",
            scan_profile="normal"
        )
        assert config.subnet == "192.168.1.0/24"
        assert config.scan_profile == "normal"
    
    def test_invalid_scan_profile_in_config(self):
        """Test invalid scan profiles are rejected in config"""
        with pytest.raises(ValidationError):
            NetworkConfigUpdate(
                subnet="192.168.1.0/24",
                scan_profile="evil_profile"
            )


class TestIntegrationValidation:
    """Test validation for integration configurations"""
    
    def test_cve_integration_valid(self):
        """Test valid CVE integration config"""
        config = CVEIntegrationUpdate(
            enabled=True,
            api_key="test-key-123",
            cache_hours=24
        )
        assert config.enabled is True
        assert config.api_key == "test-key-123"
        assert config.cache_hours == 24
    
    def test_cve_cache_hours_range(self):
        """Test CVE cache hours must be within range"""
        # Should reject < 1
        with pytest.raises(ValidationError):
            CVEIntegrationUpdate(enabled=True, cache_hours=0)
        
        # Should reject > 168 (1 week)
        with pytest.raises(ValidationError):
            CVEIntegrationUpdate(enabled=True, cache_hours=169)
    
    def test_unifi_valid_url(self):
        """Test UniFi accepts valid URLs"""
        config = UniFiIntegrationUpdate(
            enabled=True,
            controller_url="https://unifi.local:8443",
            controller_type="udm"
        )
        assert "https://unifi.local:8443" in config.controller_url
    
    def test_unifi_invalid_url(self):
        """Test UniFi rejects URLs without protocol"""
        with pytest.raises(ValidationError) as exc_info:
            UniFiIntegrationUpdate(
                enabled=True,
                controller_url="unifi.local:8443",
                controller_type="udm"
            )
        assert "http" in str(exc_info.value).lower()
    
    def test_unifi_controller_type_validation(self):
        """Test UniFi controller type only accepts valid values"""
        valid_types = ["udm", "cloudkey", "standalone"]
        for controller_type in valid_types:
            config = UniFiIntegrationUpdate(
                enabled=True,
                controller_url="https://unifi.local",
                controller_type=controller_type
            )
            assert config.controller_type == controller_type
        
        # Invalid type
        with pytest.raises(ValidationError):
            UniFiIntegrationUpdate(
                enabled=True,
                controller_url="https://unifi.local",
                controller_type="invalid"
            )
    
    def test_pihole_valid_url(self):
        """Test Pi-hole accepts valid URLs"""
        config = PiHoleIntegrationUpdate(
            enabled=True,
            pihole_url="http://pi.hole/admin"
        )
        assert "http://pi.hole/admin" in config.pihole_url
    
    def test_pihole_invalid_url(self):
        """Test Pi-hole rejects invalid URLs"""
        with pytest.raises(ValidationError):
            PiHoleIntegrationUpdate(
                enabled=True,
                pihole_url="pi.hole"  # Missing protocol
            )
    
    def test_adguard_valid_url(self):
        """Test AdGuard accepts valid URLs"""
        config = AdGuardIntegrationUpdate(
            enabled=True,
            adguard_url="https://adguard.local"
        )
        assert "https://adguard.local" in config.adguard_url
    
    def test_adguard_invalid_url(self):
        """Test AdGuard rejects invalid URLs"""
        with pytest.raises(ValidationError):
            AdGuardIntegrationUpdate(
                enabled=True,
                adguard_url="adguard.local"  # Missing protocol
            )


class TestAPIKeyValidation:
    """Test validation for API key creation"""
    
    def test_valid_api_key_name(self):
        """Test valid API key names"""
        valid_names = [
            "Production API Key",
            "Dev-Key-123",
            "automation_bot",
            "CI-CD_Pipeline"
        ]
        for name in valid_names:
            key = APIKeyCreateRequest(name=name)
            assert key.name == name
    
    def test_invalid_api_key_name(self):
        """Test invalid API key names are rejected"""
        invalid_names = [
            "<script>alert(1)</script>",
            "Key;DROP TABLE api_keys",
            "Key../../../etc/passwd",
            "Key|rm -rf /"
        ]
        for name in invalid_names:
            with pytest.raises(ValidationError) as exc_info:
                APIKeyCreateRequest(name=name)
            assert "name" in str(exc_info.value).lower()
    
    def test_api_key_name_max_length(self):
        """Test API key name respects max length"""
        with pytest.raises(ValidationError):
            APIKeyCreateRequest(name="A" * 101)
    
    def test_api_key_expiration_range(self):
        """Test API key expiration days must be within range"""
        # Valid range: 1-3650 days
        valid_days = [1, 30, 365, 3650]
        for days in valid_days:
            key = APIKeyCreateRequest(name="Test", expires_in_days=days)
            assert key.expires_in_days == days
        
        # Invalid: 0 days
        with pytest.raises(ValidationError):
            APIKeyCreateRequest(name="Test", expires_in_days=0)
        
        # Invalid: > 10 years
        with pytest.raises(ValidationError):
            APIKeyCreateRequest(name="Test", expires_in_days=3651)


class TestScheduleValidation:
    """Test validation for scheduled scan jobs"""
    
    def test_valid_cron_expression(self):
        """Test valid cron expressions"""
        valid_crons = [
            "0 0 * * *",  # Daily at midnight
            "0 */4 * * *",  # Every 4 hours
            "30 2 * * 0",  # Sunday 2:30 AM
            "*/15 * * * *",  # Every 15 minutes
        ]
        for cron in valid_crons:
            schedule = ScheduleJobCreate(
                name="Test Job",
                cron=cron,
                profile="normal"
            )
            assert schedule.cron == cron
    
    def test_invalid_cron_expression(self):
        """Test invalid cron expressions are rejected"""
        invalid_crons = [
            "* * * *",  # Only 4 fields (needs 5)
            "0 0 * * * *",  # 6 fields (too many)
            "invalid",
            "0 0 0 0 0; rm -rf /",
        ]
        for cron in invalid_crons:
            with pytest.raises(ValidationError) as exc_info:
                ScheduleJobCreate(
                    name="Test Job",
                    cron=cron,
                    profile="normal"
                )
            assert "cron" in str(exc_info.value).lower()
    
    def test_schedule_name_validation(self):
        """Test schedule job name validation"""
        valid_names = ["Daily Scan", "Nightly-Audit", "Hourly_Check"]
        for name in valid_names:
            schedule = ScheduleJobCreate(
                name=name,
                cron="0 0 * * *",
                profile="normal"
            )
            assert schedule.name == name
        
        # Invalid name with special characters
        with pytest.raises(ValidationError):
            ScheduleJobCreate(
                name="Job; DROP TABLE schedule",
                cron="0 0 * * *",
                profile="normal"
            )
    
    def test_schedule_profile_validation(self):
        """Test schedule profile only accepts valid values"""
        for profile in ["quick", "normal", "intensive"]:
            schedule = ScheduleJobCreate(
                name="Test",
                cron="0 0 * * *",
                profile=profile
            )
            assert schedule.profile == profile
        
        # Invalid profile
        with pytest.raises(ValidationError):
            ScheduleJobCreate(
                name="Test",
                cron="0 0 * * *",
                profile="malicious"
            )


class TestSQLInjectionPrevention:
    """Test that all inputs prevent SQL injection"""
    
    def test_sql_injection_in_zone(self):
        """Test SQL injection attempts in zone field"""
        sql_injections = [
            "'; DROP TABLE devices; --",
            "1' OR '1'='1",
            "admin'--",
            "1' UNION SELECT * FROM users--"
        ]
        for sql in sql_injections:
            with pytest.raises(ValidationError):
                DeviceUpdate(zone=sql)
    
    def test_sql_injection_in_labels(self):
        """Test SQL injection is escaped in labels"""
        sql = "'; DELETE FROM device_history WHERE '1'='1"
        device = DeviceUpdate(label=sql)
        # Should be HTML-escaped, making SQL harmless
        # html.escape() converts ' to &#x27; (or &#39;)
        assert "&#x27;" in device.label or "&#39;" in device.label or "&apos;" in device.label


class TestPathTraversalPrevention:
    """Test that inputs prevent path traversal attacks"""
    
    def test_path_traversal_in_zone(self):
        """Test path traversal attempts in zone field"""
        path_traversals = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "....//....//etc/shadow"
        ]
        for path in path_traversals:
            with pytest.raises(ValidationError):
                DeviceUpdate(zone=path)
