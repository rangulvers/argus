"""UniFi data models"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum


class ConnectionType(str, Enum):
    """Client connection type"""
    WIRED = "wired"
    WIRELESS = "wireless"
    VPN = "vpn"
    UNKNOWN = "unknown"


@dataclass
class UniFiClient:
    """Represents a client device from UniFi Controller"""

    # Identity
    mac: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    name: Optional[str] = None  # User-assigned name in UniFi

    # Connection info
    connection_type: ConnectionType = ConnectionType.UNKNOWN
    is_wired: bool = False
    is_guest: bool = False

    # Wireless info (if wireless)
    ssid: Optional[str] = None
    bssid: Optional[str] = None  # AP MAC address
    channel: Optional[int] = None
    radio: Optional[str] = None  # "na" (5GHz) or "ng" (2.4GHz)
    signal: Optional[int] = None  # Signal strength in dBm
    rssi: Optional[int] = None
    noise: Optional[int] = None
    tx_rate: Optional[int] = None  # TX rate in Kbps
    rx_rate: Optional[int] = None  # RX rate in Kbps

    # Wired info (if wired)
    switch_mac: Optional[str] = None  # Connected switch MAC
    switch_port: Optional[int] = None  # Switch port number

    # Connection state
    is_online: bool = False
    uptime: Optional[int] = None  # Uptime in seconds
    last_seen: Optional[datetime] = None
    first_seen: Optional[datetime] = None

    # Traffic stats
    tx_bytes: int = 0
    rx_bytes: int = 0
    tx_packets: int = 0
    rx_packets: int = 0

    # Device identification
    oui: Optional[str] = None  # Manufacturer from OUI
    fingerprint: Optional[Dict[str, Any]] = None
    device_type: Optional[str] = None  # UniFi's device type guess

    # Network info
    network: Optional[str] = None  # Network/VLAN name
    network_id: Optional[str] = None
    vlan: Optional[int] = None

    # Raw data for debugging
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UniFiDevice:
    """Represents a UniFi network device (AP, switch, gateway)"""
    mac: str
    name: str
    model: str
    ip: Optional[str] = None
    version: Optional[str] = None
    state: str = "unknown"
    clients_count: int = 0
    type: str = "unknown"  # uap, usw, ugw


@dataclass
class UniFiSiteHealth:
    """Health status of a UniFi site"""
    num_aps: int = 0
    num_switches: int = 0
    num_gateways: int = 0
    num_clients: int = 0
    num_guests: int = 0
    wan_ip: Optional[str] = None
    isp_name: Optional[str] = None
    uptime: Optional[int] = None
