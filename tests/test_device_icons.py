"""Tests for device icon detection"""

import pytest
from app.utils.device_icons import (
    detect_device_type,
    get_device_icon_info,
    detect_and_get_icon,
    DEVICE_TYPES,
)


class TestDeviceTypeDetection:
    """Tests for device type detection"""

    def test_detect_router_by_vendor(self):
        """Test detecting router by vendor"""
        assert detect_device_type(vendor="Cisco Systems") == "router"
        assert detect_device_type(vendor="NETGEAR Inc") == "router"
        assert detect_device_type(vendor="TP-Link Technologies") == "router"
        assert detect_device_type(vendor="Linksys") == "router"

    def test_detect_phone_by_vendor(self):
        """Test detecting phone by vendor"""
        assert detect_device_type(vendor="Apple Inc") == "phone"
        assert detect_device_type(vendor="Samsung Electronics") == "phone"
        assert detect_device_type(vendor="Huawei Technologies") == "phone"
        assert detect_device_type(vendor="Xiaomi Communications") == "phone"

    def test_detect_server_by_vendor(self):
        """Test detecting server by vendor"""
        assert detect_device_type(vendor="Dell Inc.") == "server"
        assert detect_device_type(vendor="Hewlett Packard Enterprise") == "server"
        assert detect_device_type(vendor="Supermicro") == "server"

    def test_detect_printer_by_vendor(self):
        """Test detecting printer by vendor"""
        assert detect_device_type(vendor="Brother Industries") == "printer"
        assert detect_device_type(vendor="Canon Inc") == "printer"
        assert detect_device_type(vendor="Epson") == "printer"

    def test_detect_nas_by_vendor(self):
        """Test detecting NAS by vendor"""
        assert detect_device_type(vendor="Synology Inc") == "nas"
        assert detect_device_type(vendor="QNAP Systems") == "nas"

    def test_detect_camera_by_vendor(self):
        """Test detecting camera by vendor"""
        assert detect_device_type(vendor="Hikvision") == "camera"
        assert detect_device_type(vendor="Dahua Technology") == "camera"

    def test_detect_by_hostname(self):
        """Test detecting device by hostname patterns"""
        assert detect_device_type(hostname="iphone-john") == "phone"
        assert detect_device_type(hostname="my-macbook-pro") == "laptop"
        assert detect_device_type(hostname="web-server-01") == "server"
        assert detect_device_type(hostname="office-printer") == "printer"
        assert detect_device_type(hostname="nas-storage") == "nas"

    def test_detect_by_os_name(self):
        """Test detecting device by OS name"""
        assert detect_device_type(os_name="iOS 17.0") == "phone"
        assert detect_device_type(os_name="Android 14") == "phone"
        assert detect_device_type(os_name="Windows Server 2022") == "server"
        assert detect_device_type(os_name="Ubuntu 22.04 LTS") == "server"
        assert detect_device_type(os_name="Windows 11 Pro") == "desktop"

    def test_detect_router_by_ip(self):
        """Test detecting router by gateway IP"""
        assert detect_device_type(ip_address="192.168.1.1") == "router"
        assert detect_device_type(ip_address="10.0.0.254") == "router"

    def test_detect_by_ports(self):
        """Test detecting device by open ports"""
        assert detect_device_type(ports=[9100]) == "printer"
        assert detect_device_type(ports=[631]) == "printer"
        assert detect_device_type(ports=[5000, 5001]) == "nas"

    def test_explicit_device_type_takes_priority(self):
        """Test that explicit device_type takes priority"""
        result = detect_device_type(
            device_type="server",
            vendor="Apple Inc",  # Would normally be phone
            hostname="iphone"  # Would normally be phone
        )
        assert result == "server"

    def test_unknown_device(self):
        """Test unknown device when no patterns match"""
        assert detect_device_type() == "unknown"
        assert detect_device_type(vendor="Unknown Corp") == "unknown"
        assert detect_device_type(ip_address="192.168.1.50") == "unknown"

    def test_case_insensitive_matching(self):
        """Test case insensitive pattern matching"""
        assert detect_device_type(vendor="APPLE INC") == "phone"
        assert detect_device_type(vendor="apple inc") == "phone"
        assert detect_device_type(hostname="IPHONE-USER") == "phone"
        assert detect_device_type(hostname="iPhone-User") == "phone"


class TestDeviceIconInfo:
    """Tests for device icon info retrieval"""

    def test_get_icon_info_valid(self):
        """Test getting icon info for valid device types"""
        for device_type in DEVICE_TYPES.keys():
            info = get_device_icon_info(device_type)
            assert "label" in info
            assert "icon" in info
            assert len(info["label"]) > 0

    def test_get_icon_info_unknown(self):
        """Test getting icon info for unknown type"""
        info = get_device_icon_info("nonexistent")
        assert info == DEVICE_TYPES["unknown"]

    def test_all_device_types_have_info(self):
        """Test all device types have required info"""
        required_fields = ["label", "icon"]
        for dtype, info in DEVICE_TYPES.items():
            for field in required_fields:
                assert field in info, f"Device type '{dtype}' missing '{field}'"


class TestDetectAndGetIcon:
    """Tests for combined detect and get icon function"""

    def test_detect_and_get_icon_complete(self):
        """Test detect_and_get_icon returns complete info"""
        result = detect_and_get_icon(vendor="Apple Inc")

        assert "type" in result
        assert "label" in result
        assert "icon" in result
        assert result["type"] == "phone"
        assert result["label"] == "Smartphone"

    def test_detect_and_get_icon_with_all_params(self):
        """Test detect_and_get_icon with all parameters"""
        result = detect_and_get_icon(
            vendor="Dell Inc.",
            hostname="web-server",
            os_name="Ubuntu 22.04",
            ports=[22, 80, 443],
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_address="192.168.1.100"
        )

        assert result["type"] == "server"

    def test_detect_and_get_icon_unknown(self):
        """Test detect_and_get_icon for unknown device"""
        result = detect_and_get_icon()

        assert result["type"] == "unknown"
        assert result["label"] == "Unknown Device"


class TestSpecificDeviceTypes:
    """Tests for specific device type detections"""

    def test_smart_home_devices(self):
        """Test smart home device detection"""
        assert detect_device_type(vendor="Amazon Technologies") == "smart_home"
        assert detect_device_type(hostname="echo-dot") == "smart_home"
        assert detect_device_type(hostname="google-home-mini") == "smart_home"

    def test_gaming_devices(self):
        """Test gaming device detection"""
        assert detect_device_type(vendor="Sony Interactive Entertainment") == "gaming"
        assert detect_device_type(hostname="playstation-5") == "gaming"
        assert detect_device_type(os_name="PlayStation System Software") == "gaming"

    def test_tv_devices(self):
        """Test TV device detection"""
        assert detect_device_type(vendor="Roku Inc") == "tv"
        assert detect_device_type(hostname="living-room-tv") == "tv"
        assert detect_device_type(os_name="Tizen 7.0") == "tv"

    def test_iot_devices(self):
        """Test IoT device detection"""
        assert detect_device_type(vendor="Espressif Inc") == "iot"
        assert detect_device_type(vendor="Tuya Smart") == "iot"

    def test_access_point(self):
        """Test access point detection"""
        assert detect_device_type(vendor="Ubiquiti Networks") == "access_point"
        assert detect_device_type(hostname="unifi-ap-office") == "access_point"

    def test_network_switch(self):
        """Test network switch detection"""
        assert detect_device_type(hostname="core-switch-01") == "switch"


class TestEdgeCases:
    """Tests for edge cases"""

    def test_empty_strings(self):
        """Test handling of empty strings"""
        assert detect_device_type(vendor="") == "unknown"
        assert detect_device_type(hostname="") == "unknown"
        assert detect_device_type(os_name="") == "unknown"

    def test_none_values(self):
        """Test handling of None values"""
        assert detect_device_type(vendor=None) == "unknown"
        assert detect_device_type(hostname=None) == "unknown"
        assert detect_device_type(ports=None) == "unknown"

    def test_empty_ports_list(self):
        """Test handling of empty ports list"""
        assert detect_device_type(ports=[]) == "unknown"

    def test_priority_order(self):
        """Test detection priority order"""
        # Vendor should take priority over hostname
        result = detect_device_type(
            vendor="Cisco Systems",
            hostname="iphone-user"
        )
        assert result == "router"

        # Hostname should take priority over ports
        result = detect_device_type(
            hostname="web-server",
            ports=[9100]  # Would be printer
        )
        assert result == "server"
