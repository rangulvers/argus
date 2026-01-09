"""Pytest fixtures for Argus test suite"""

import os
import sys
import tempfile
import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Set test environment BEFORE importing any app modules
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["TESTING"] = "true"

# Create the test engine BEFORE importing app modules
# This ensures that when app modules import database, they get our test engine
_test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False}
)
_TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_test_engine)

# Patch the database module before any app imports
from app import database
database.engine = _test_engine
database.SessionLocal = _TestingSessionLocal

# Define a new get_db that uses the test session
def _override_get_db():
    db = _TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

database.get_db = _override_get_db

# NOW import the rest of the app modules
from app.database import Base
from app.models import Scan, Device, Port, Change, DeviceHistory, User
from app.auth import hash_password

# Create all tables
Base.metadata.create_all(bind=_test_engine)


@pytest.fixture(scope="function")
def test_engine():
    """Return the test database engine"""
    # Clear all data between tests
    Base.metadata.drop_all(bind=_test_engine)
    Base.metadata.create_all(bind=_test_engine)
    yield _test_engine


@pytest.fixture(scope="function")
def test_db(test_engine):
    """Create a test database session"""
    db = _TestingSessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


@pytest.fixture(scope="function")
def client(test_engine, test_db):
    """Create a test client"""
    from fastapi.testclient import TestClient
    from app.main import app

    # Ensure dependency overrides are set
    app.dependency_overrides[database.get_db] = _override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def sample_scan(test_db):
    """Create a sample scan for testing"""
    scan = Scan(
        subnet="192.168.1.0/24",
        scan_profile="normal",
        status="completed",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        devices_found=3
    )
    test_db.add(scan)
    test_db.commit()
    test_db.refresh(scan)
    return scan


@pytest.fixture
def sample_device(test_db, sample_scan):
    """Create a sample device for testing"""
    device = Device(
        scan_id=sample_scan.id,
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        hostname="test-device",
        vendor="Test Vendor",
        device_type="server",
        os_name="Linux",
        status="up",
        risk_level="low",
        risk_score=15,
        is_trusted=False
    )
    test_db.add(device)
    test_db.commit()
    test_db.refresh(device)
    return device


@pytest.fixture
def sample_device_with_ports(test_db, sample_scan):
    """Create a sample device with ports for testing"""
    device = Device(
        scan_id=sample_scan.id,
        ip_address="192.168.1.101",
        mac_address="11:22:33:44:55:66",
        hostname="web-server",
        vendor="Dell Inc.",
        device_type="server",
        os_name="Ubuntu 22.04",
        status="up",
        risk_level="medium",
        risk_score=35,
        is_trusted=True
    )
    test_db.add(device)
    test_db.commit()
    test_db.refresh(device)

    # Add ports
    ports = [
        Port(device_id=device.id, port_number=22, protocol="tcp", state="open", service_name="ssh"),
        Port(device_id=device.id, port_number=80, protocol="tcp", state="open", service_name="http"),
        Port(device_id=device.id, port_number=443, protocol="tcp", state="open", service_name="https"),
    ]
    for port in ports:
        test_db.add(port)
    test_db.commit()

    test_db.refresh(device)
    return device


@pytest.fixture
def sample_user(test_db):
    """Create a sample admin user for testing"""
    user = User(
        username="admin",
        password_hash=hash_password("testpassword123")
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


@pytest.fixture
def authenticated_client(client, sample_user):
    """Create a test client with authenticated session"""
    # Login to get session cookie
    response = client.post(
        "/login",
        data={"username": "admin", "password": "testpassword123"},
        follow_redirects=False
    )
    return client


@pytest.fixture
def sample_changes(test_db, sample_scan):
    """Create sample changes for testing"""
    changes = [
        Change(
            scan_id=sample_scan.id,
            change_type="new_device",
            severity="info",
            device_ip="192.168.1.100",
            device_mac="AA:BB:CC:DD:EE:FF",
            description="New device detected"
        ),
        Change(
            scan_id=sample_scan.id,
            change_type="new_port",
            severity="warning",
            device_ip="192.168.1.101",
            port_number=22,
            protocol="tcp",
            description="New port 22/tcp opened"
        ),
    ]
    for change in changes:
        test_db.add(change)
    test_db.commit()
    return changes


@pytest.fixture
def sample_device_history(test_db):
    """Create sample device history for testing"""
    history = DeviceHistory(
        mac_address="AA:BB:CC:DD:EE:FF",
        last_ip="192.168.1.100",
        last_hostname="test-device",
        label="My Test Device",
        is_trusted=True,
        notes="Test notes",
        zone="Servers",
        times_seen=5
    )
    test_db.add(history)
    test_db.commit()
    test_db.refresh(history)
    return history


@pytest.fixture
def multiple_devices(test_db, sample_scan):
    """Create multiple devices with different characteristics"""
    devices_data = [
        {
            "ip_address": "192.168.1.1",
            "mac_address": "00:11:22:33:44:55",
            "hostname": "router",
            "vendor": "Cisco Systems",
            "risk_level": "none",
            "risk_score": 0,
        },
        {
            "ip_address": "192.168.1.50",
            "mac_address": "AA:BB:CC:DD:EE:01",
            "hostname": "iphone-user",
            "vendor": "Apple Inc.",
            "risk_level": "none",
            "risk_score": 0,
        },
        {
            "ip_address": "192.168.1.100",
            "mac_address": "AA:BB:CC:DD:EE:02",
            "hostname": "nas-storage",
            "vendor": "Synology",
            "risk_level": "low",
            "risk_score": 10,
        },
        {
            "ip_address": "192.168.1.200",
            "mac_address": "AA:BB:CC:DD:EE:03",
            "hostname": "old-server",
            "vendor": "Dell Inc.",
            "risk_level": "high",
            "risk_score": 75,
        },
    ]

    devices = []
    for data in devices_data:
        device = Device(scan_id=sample_scan.id, status="up", **data)
        test_db.add(device)
        devices.append(device)

    test_db.commit()
    for device in devices:
        test_db.refresh(device)

    return devices


@pytest.fixture
def temp_config_file():
    """Create a temporary config file for testing"""
    config_content = """
network:
  subnet: "192.168.1.0/24"
  scan_profile: "normal"

scanning:
  port_range: "1-1000"
  timeout: 300

database:
  path: "./data/test.db"

notifications:
  enabled: false
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        f.flush()
        yield f.name
    os.unlink(f.name)
