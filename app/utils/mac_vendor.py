"""MAC address vendor lookup using Wireshark manuf database"""

import os
import re
import logging
from pathlib import Path
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta
import urllib.request

logger = logging.getLogger(__name__)

# Wireshark manuf file URL
MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"

# Cache settings
CACHE_DIR = Path(__file__).parent.parent.parent / "data"
MANUF_FILE = CACHE_DIR / "manuf"
CACHE_MAX_AGE_DAYS = 7

# Device type hints based on vendor names
DEVICE_TYPE_HINTS = {
    # Smartphones/Tablets
    "apple": "Apple Device",
    "samsung electro": "Samsung Device",
    "huawei": "Huawei Device",
    "xiaomi": "Xiaomi Device",
    "oneplus": "OnePlus Phone",
    "google": "Google Device",
    "motorola": "Motorola Device",

    # Computers
    "dell": "Dell Computer",
    "hewlett": "HP Computer",
    "lenovo": "Lenovo Computer",
    "asus": "ASUS Computer",
    "acer": "Acer Computer",
    "microsoft": "Microsoft Device",
    "intel": "Intel-based Device",
    "amd": "AMD-based Device",

    # Network Equipment
    "cisco": "Cisco Network Device",
    "netgear": "Netgear Router/Switch",
    "tp-link": "TP-Link Router/Switch",
    "d-link": "D-Link Router/Switch",
    "ubiquiti": "Ubiquiti Network Device",
    "linksys": "Linksys Router",
    "zyxel": "ZyXEL Network Device",
    "aruba": "Aruba Network Device",
    "mikrotik": "MikroTik Router",
    "juniper": "Juniper Network Device",

    # IoT / Smart Home
    "raspberry pi": "Raspberry Pi",
    "espressif": "ESP32/ESP8266 IoT Device",
    "amazon": "Amazon Echo/Fire Device",
    "ring": "Ring Doorbell/Camera",
    "nest": "Nest Smart Device",
    "philips": "Philips Device",
    "sonos": "Sonos Speaker",
    "ecobee": "Ecobee Thermostat",
    "wyze": "Wyze Camera",
    "tuya": "Tuya Smart Device",
    "shenzhen": "Chinese IoT Device",

    # Gaming
    "sony": "Sony/PlayStation Device",
    "nintendo": "Nintendo Device",
    "valve": "Steam/Valve Device",

    # Printers
    "canon": "Canon Printer",
    "epson": "Epson Printer",
    "brother": "Brother Printer",
    "xerox": "Xerox Printer",

    # NAS / Storage
    "synology": "Synology NAS",
    "qnap": "QNAP NAS",
    "western digital": "WD NAS/Storage",
    "seagate": "Seagate Storage",

    # Security Cameras
    "hikvision": "Hikvision Camera",
    "dahua": "Dahua Camera",
    "axis": "Axis Camera",
    "reolink": "Reolink Camera",

    # Smart TV
    "lg electro": "LG TV/Device",
    "tcl": "TCL TV",
    "roku": "Roku Streaming Device",
    "vizio": "Vizio TV",

    # Virtual Machines
    "vmware": "VMware Virtual Machine",
    "virtualbox": "VirtualBox VM",
    "xen": "Xen Virtual Machine",
    "parallels": "Parallels VM",
}


class MacVendorLookup:
    """Lookup MAC address vendors using Wireshark manuf database"""

    def __init__(self):
        self._vendors: Dict[str, Tuple[str, str]] = {}  # prefix -> (short_name, full_name)
        self._loaded = False

    def _ensure_cache_dir(self):
        """Create cache directory if it doesn't exist"""
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    def _is_cache_valid(self) -> bool:
        """Check if cached manuf file exists and is recent enough"""
        if not MANUF_FILE.exists():
            return False

        mtime = datetime.fromtimestamp(MANUF_FILE.stat().st_mtime)
        age = datetime.now() - mtime
        return age < timedelta(days=CACHE_MAX_AGE_DAYS)

    def _download_manuf(self) -> bool:
        """Download manuf file from Wireshark"""
        try:
            logger.info(f"Downloading manuf file from {MANUF_URL}")
            self._ensure_cache_dir()

            req = urllib.request.Request(
                MANUF_URL,
                headers={'User-Agent': 'Argus/1.0'}
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read()

            with open(MANUF_FILE, 'wb') as f:
                f.write(content)

            logger.info(f"Manuf file downloaded successfully ({len(content)} bytes)")
            return True

        except Exception as e:
            logger.error(f"Failed to download manuf file: {e}")
            return False

    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address to uppercase colon-separated format"""
        # Remove common separators and convert to uppercase
        mac = mac.upper().replace('-', '').replace(':', '').replace('.', '')
        # Insert colons
        return ':'.join(mac[i:i+2] for i in range(0, len(mac), 2))

    def _get_prefixes(self, mac: str) -> list:
        """Get all possible prefixes to check (24, 28, 36 bit)"""
        mac = self._normalize_mac(mac)
        parts = mac.split(':')

        prefixes = []
        # 24-bit (OUI) - first 3 octets
        if len(parts) >= 3:
            prefixes.append(':'.join(parts[:3]))
        # 28-bit - first 3.5 octets
        if len(parts) >= 4:
            prefixes.append(':'.join(parts[:3]) + ':' + parts[3][0])
        # 36-bit - first 4.5 octets
        if len(parts) >= 5:
            prefixes.append(':'.join(parts[:4]) + ':' + parts[4][0])

        # Return in order of specificity (most specific first)
        return list(reversed(prefixes))

    def _parse_manuf_file(self):
        """Parse the manuf file into memory"""
        if not MANUF_FILE.exists():
            logger.warning("Manuf file not found")
            return

        try:
            with open(MANUF_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()

                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue

                    # Parse tab-separated values
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        prefix = parts[0].strip().upper()
                        short_name = parts[1].strip() if len(parts) > 1 else ""
                        full_name = parts[2].strip() if len(parts) > 2 else short_name

                        # Normalize prefix format
                        prefix = prefix.replace('-', ':')

                        self._vendors[prefix] = (short_name, full_name)

            logger.info(f"Loaded {len(self._vendors)} vendor entries from manuf file")
            self._loaded = True

        except Exception as e:
            logger.error(f"Failed to parse manuf file: {e}")

    def load(self, force_download: bool = False):
        """Load the manuf database, downloading if necessary"""
        if self._loaded and not force_download:
            return

        if force_download or not self._is_cache_valid():
            self._download_manuf()

        self._parse_manuf_file()

    def lookup(self, mac: str) -> Optional[Dict[str, str]]:
        """
        Look up vendor information for a MAC address

        Args:
            mac: MAC address in any common format

        Returns:
            Dict with 'short_name', 'full_name', and 'device_type' if found
        """
        if not mac:
            return None

        self.load()

        if not self._vendors:
            return None

        prefixes = self._get_prefixes(mac)

        for prefix in prefixes:
            if prefix in self._vendors:
                short_name, full_name = self._vendors[prefix]

                # Try to determine device type
                device_type = self._guess_device_type(full_name)

                return {
                    'short_name': short_name,
                    'full_name': full_name,
                    'device_type': device_type,
                    'prefix': prefix
                }

        return None

    def _guess_device_type(self, vendor_name: str) -> Optional[str]:
        """Guess device type based on vendor name"""
        if not vendor_name:
            return None

        vendor_lower = vendor_name.lower()

        for keyword, device_type in DEVICE_TYPE_HINTS.items():
            if keyword in vendor_lower:
                return device_type

        return None

    def get_vendor_name(self, mac: str) -> Optional[str]:
        """Get just the vendor name for a MAC address"""
        result = self.lookup(mac)
        return result['full_name'] if result else None

    def get_device_type(self, mac: str) -> Optional[str]:
        """Get device type hint for a MAC address"""
        result = self.lookup(mac)
        return result['device_type'] if result else None


# Singleton instance
_vendor_lookup = None

def get_vendor_lookup() -> MacVendorLookup:
    """Get the singleton MacVendorLookup instance"""
    global _vendor_lookup
    if _vendor_lookup is None:
        _vendor_lookup = MacVendorLookup()
    return _vendor_lookup


def lookup_mac_vendor(mac: str) -> Optional[Dict[str, str]]:
    """Convenience function to lookup MAC vendor"""
    return get_vendor_lookup().lookup(mac)
