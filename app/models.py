"""Database models for Argus"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class Scan(Base):
    """Represents a network scan"""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="running", nullable=False)  # running, completed, failed
    scan_type = Column(String(20), default="network", nullable=False)  # network, device
    scan_profile = Column(String(20), default="normal")  # quick, normal, intensive
    subnet = Column(String(50), nullable=False)
    devices_found = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

    # Relationships
    devices = relationship("Device", back_populates="scan", cascade="all, delete-orphan")
    changes = relationship("Change", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan {self.id} - {self.started_at} - {self.status}>"


class Device(Base):
    """Represents a discovered network device"""
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)  # IPv4 or IPv6
    mac_address = Column(String(17), nullable=True, index=True)  # XX:XX:XX:XX:XX:XX
    hostname = Column(String(255), nullable=True)
    vendor = Column(String(255), nullable=True)  # MAC vendor lookup
    device_type = Column(String(100), nullable=True)  # Guessed device type (e.g., "Raspberry Pi", "iPhone")
    os_name = Column(String(255), nullable=True)
    os_accuracy = Column(Integer, nullable=True)  # OS detection accuracy %
    status = Column(String(20), default="up")  # up, down
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # User-defined fields
    label = Column(String(255), nullable=True)  # User-friendly label
    is_trusted = Column(Boolean, default=False)  # Whitelisted device
    notes = Column(Text, nullable=True)
    zone = Column(String(100), nullable=True)  # Network zone (e.g., "IoT", "Servers", "Guest")

    # Threat detection fields
    risk_level = Column(String(20), default="none")  # none, low, medium, high, critical
    risk_score = Column(Integer, default=0)  # 0-100
    threat_summary = Column(Text, nullable=True)  # Human-readable summary
    threat_details = Column(JSON, nullable=True)  # Detailed threat info as JSON

    # Relationships
    scan = relationship("Scan", back_populates="devices")
    ports = relationship("Port", back_populates="device", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Device {self.ip_address} - {self.mac_address}>"


class Port(Base):
    """Represents an open port on a device"""
    __tablename__ = "ports"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    port_number = Column(Integer, nullable=False, index=True)
    protocol = Column(String(10), nullable=False)  # tcp, udp
    state = Column(String(20), nullable=False)  # open, closed, filtered
    service_name = Column(String(100), nullable=True)
    service_product = Column(String(100), nullable=True)
    service_version = Column(String(100), nullable=True)
    service_extra_info = Column(Text, nullable=True)

    # Relationships
    device = relationship("Device", back_populates="ports")

    def __repr__(self):
        return f"<Port {self.port_number}/{self.protocol} - {self.state}>"


class Change(Base):
    """Represents a detected change between scans"""
    __tablename__ = "changes"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    change_type = Column(String(50), nullable=False, index=True)  # device_added, device_removed, port_opened, port_closed, service_changed
    severity = Column(String(20), default="info")  # info, warning, critical
    device_ip = Column(String(45), nullable=True)
    device_mac = Column(String(17), nullable=True)
    port_number = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    description = Column(Text, nullable=False)
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    acknowledged = Column(Boolean, default=False)

    # Relationships
    scan = relationship("Scan", back_populates="changes")
    alerts = relationship("Alert", back_populates="change", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Change {self.change_type} - {self.device_ip}>"


class Alert(Base):
    """Represents an alert triggered by a change"""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    change_id = Column(Integer, ForeignKey("changes.id"), nullable=False, index=True)
    alert_type = Column(String(50), nullable=False)  # email, webhook, ui
    status = Column(String(20), default="pending")  # pending, sent, failed
    sent_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    extra_data = Column(JSON, nullable=True)  # Additional alert data

    # Relationships
    change = relationship("Change", back_populates="alerts")

    def __repr__(self):
        return f"<Alert {self.alert_type} - {self.status}>"


class DeviceHistory(Base):
    """Tracks device history across scans for persistent identification"""
    __tablename__ = "device_history"

    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String(17), nullable=False, unique=True, index=True)
    last_ip = Column(String(45), nullable=True)
    last_hostname = Column(String(255), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    times_seen = Column(Integer, default=1)

    # User-defined persistent fields
    label = Column(String(255), nullable=True)
    is_trusted = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
    zone = Column(String(100), nullable=True)  # Network zone

    def __repr__(self):
        return f"<DeviceHistory {self.mac_address} - {self.last_ip}>"


class User(Base):
    """Represents an admin user for authentication"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.username}>"


class APIKey(Base):
    """Represents an API key for programmatic access"""
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)  # User-friendly name for the key
    key_hash = Column(String(255), nullable=False)  # Hashed API key
    key_prefix = Column(String(8), nullable=False)  # First 8 chars for identification
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)  # Optional expiration
    is_revoked = Column(Boolean, default=False)

    # Relationships
    user = relationship("User", back_populates="api_keys")

    def __repr__(self):
        return f"<APIKey {self.key_prefix}... - {self.name}>"
