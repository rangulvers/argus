"""Tests for database models"""

import pytest
from datetime import datetime
from app.models import Scan, Device, Port, Change, DeviceHistory, User


class TestScanModel:
    """Tests for Scan model"""

    def test_create_scan(self, test_db):
        """Test creating a new scan"""
        scan = Scan(
            subnet="192.168.1.0/24",
            scan_profile="normal",
            status="running"
        )
        test_db.add(scan)
        test_db.commit()

        assert scan.id is not None
        assert scan.subnet == "192.168.1.0/24"
        assert scan.scan_profile == "normal"
        assert scan.status == "running"
        assert scan.started_at is not None

    def test_scan_status_transitions(self, test_db):
        """Test scan status can be updated"""
        scan = Scan(subnet="10.0.0.0/24", status="running")
        test_db.add(scan)
        test_db.commit()

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.devices_found = 10
        test_db.commit()

        test_db.refresh(scan)
        assert scan.status == "completed"
        assert scan.devices_found == 10
        assert scan.completed_at is not None

    def test_scan_device_relationship(self, test_db, sample_scan, sample_device):
        """Test scan-device relationship"""
        assert sample_device.scan_id == sample_scan.id
        assert sample_device in sample_scan.devices


class TestDeviceModel:
    """Tests for Device model"""

    def test_create_device(self, test_db, sample_scan):
        """Test creating a new device"""
        device = Device(
            scan_id=sample_scan.id,
            ip_address="192.168.1.50",
            mac_address="12:34:56:78:9A:BC",
            hostname="test-host",
            vendor="Test Corp",
            status="up"
        )
        test_db.add(device)
        test_db.commit()

        assert device.id is not None
        assert device.ip_address == "192.168.1.50"
        assert device.mac_address == "12:34:56:78:9A:BC"
        assert device.is_trusted is False  # Default value

    def test_device_with_risk_assessment(self, test_db, sample_scan):
        """Test device with risk assessment fields"""
        device = Device(
            scan_id=sample_scan.id,
            ip_address="192.168.1.99",
            risk_level="high",
            risk_score=85,
            threat_summary="Multiple critical ports exposed",
            threat_details={"ports": [23, 445], "cves": ["CVE-2017-0144"]}
        )
        test_db.add(device)
        test_db.commit()

        test_db.refresh(device)
        assert device.risk_level == "high"
        assert device.risk_score == 85
        assert device.threat_details["cves"] == ["CVE-2017-0144"]

    def test_device_trusted_flag(self, test_db, sample_scan):
        """Test device trusted flag"""
        device = Device(
            scan_id=sample_scan.id,
            ip_address="192.168.1.10",
            is_trusted=True
        )
        test_db.add(device)
        test_db.commit()

        assert device.is_trusted is True

    def test_device_zone_field(self, test_db, sample_scan):
        """Test device zone field"""
        device = Device(
            scan_id=sample_scan.id,
            ip_address="192.168.1.20",
            zone="IoT Devices"
        )
        test_db.add(device)
        test_db.commit()

        assert device.zone == "IoT Devices"


class TestPortModel:
    """Tests for Port model"""

    def test_create_port(self, test_db, sample_device):
        """Test creating a new port"""
        port = Port(
            device_id=sample_device.id,
            port_number=8080,
            protocol="tcp",
            state="open",
            service_name="http-proxy"
        )
        test_db.add(port)
        test_db.commit()

        assert port.id is not None
        assert port.port_number == 8080
        assert port.service_name == "http-proxy"

    def test_port_with_service_details(self, test_db, sample_device):
        """Test port with full service details"""
        port = Port(
            device_id=sample_device.id,
            port_number=22,
            protocol="tcp",
            state="open",
            service_name="ssh",
            service_product="OpenSSH",
            service_version="8.9p1"
        )
        test_db.add(port)
        test_db.commit()

        assert port.service_product == "OpenSSH"
        assert port.service_version == "8.9p1"

    def test_device_port_relationship(self, test_db, sample_device_with_ports):
        """Test device-port relationship"""
        assert len(sample_device_with_ports.ports) == 3
        port_numbers = [p.port_number for p in sample_device_with_ports.ports]
        assert 22 in port_numbers
        assert 80 in port_numbers
        assert 443 in port_numbers


class TestChangeModel:
    """Tests for Change model"""

    def test_create_change(self, test_db, sample_scan):
        """Test creating a new change record"""
        change = Change(
            scan_id=sample_scan.id,
            change_type="new_device",
            severity="info",
            device_ip="192.168.1.150",
            description="New device discovered on network"
        )
        test_db.add(change)
        test_db.commit()

        assert change.id is not None
        assert change.change_type == "new_device"
        assert change.detected_at is not None

    def test_change_with_port_info(self, test_db, sample_scan):
        """Test change with port information"""
        change = Change(
            scan_id=sample_scan.id,
            change_type="new_port",
            severity="warning",
            device_ip="192.168.1.100",
            port_number=3389,
            protocol="tcp",
            description="RDP port opened - potential security risk"
        )
        test_db.add(change)
        test_db.commit()

        assert change.port_number == 3389
        assert change.severity == "warning"


class TestDeviceHistoryModel:
    """Tests for DeviceHistory model"""

    def test_create_device_history(self, test_db):
        """Test creating device history"""
        history = DeviceHistory(
            mac_address="FF:EE:DD:CC:BB:AA",
            last_ip="192.168.1.200",
            last_hostname="persistent-device"
        )
        test_db.add(history)
        test_db.commit()

        assert history.id is not None
        assert history.times_seen == 1  # Default value

    def test_device_history_persistence(self, test_db, sample_device_history):
        """Test device history persists user labels"""
        assert sample_device_history.label == "My Test Device"
        assert sample_device_history.is_trusted is True
        assert sample_device_history.zone == "Servers"

    def test_device_history_unique_mac(self, test_db, sample_device_history):
        """Test MAC address uniqueness constraint"""
        duplicate = DeviceHistory(
            mac_address=sample_device_history.mac_address,
            last_ip="192.168.1.999"
        )
        test_db.add(duplicate)

        with pytest.raises(Exception):  # IntegrityError
            test_db.commit()


class TestUserModel:
    """Tests for User model"""

    def test_create_user(self, test_db):
        """Test creating a new user"""
        from app.auth import hash_password

        user = User(
            username="testuser",
            password_hash=hash_password("securepassword")
        )
        test_db.add(user)
        test_db.commit()

        assert user.id is not None
        assert user.username == "testuser"
        assert user.password_hash != "securepassword"  # Should be hashed

    def test_user_unique_username(self, test_db, sample_user):
        """Test username uniqueness constraint"""
        duplicate = User(
            username="admin",  # Same as sample_user
            password_hash="somehash"
        )
        test_db.add(duplicate)

        with pytest.raises(Exception):  # IntegrityError
            test_db.commit()

    def test_user_last_login(self, test_db, sample_user):
        """Test updating last login"""
        sample_user.last_login = datetime.utcnow()
        test_db.commit()

        test_db.refresh(sample_user)
        assert sample_user.last_login is not None
