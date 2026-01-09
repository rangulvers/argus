"""Device type detection and icon mapping for Argus"""

from typing import Optional, List, Dict, Any


# Device type constants
DEVICE_TYPES = {
    "router": {"label": "Router/Gateway", "icon": "router"},
    "server": {"label": "Server", "icon": "server"},
    "desktop": {"label": "Desktop", "icon": "desktop"},
    "laptop": {"label": "Laptop", "icon": "laptop"},
    "phone": {"label": "Smartphone", "icon": "phone"},
    "tablet": {"label": "Tablet", "icon": "tablet"},
    "tv": {"label": "Smart TV", "icon": "tv"},
    "gaming": {"label": "Gaming Console", "icon": "gaming"},
    "iot": {"label": "IoT Device", "icon": "iot"},
    "printer": {"label": "Printer", "icon": "printer"},
    "nas": {"label": "Network Storage", "icon": "nas"},
    "camera": {"label": "Camera/Security", "icon": "camera"},
    "smart_home": {"label": "Smart Home", "icon": "smart_home"},
    "access_point": {"label": "Access Point", "icon": "access_point"},
    "switch": {"label": "Network Switch", "icon": "switch"},
    "unknown": {"label": "Unknown Device", "icon": "unknown"},
}

# Vendor patterns for device type detection
VENDOR_PATTERNS = {
    # Phones
    "apple": "phone",
    "samsung": "phone",
    "huawei": "phone",
    "xiaomi": "phone",
    "oneplus": "phone",
    "google": "phone",
    "motorola": "phone",
    "lg electronics": "phone",
    "oppo": "phone",
    "vivo": "phone",

    # Routers/Network
    "cisco": "router",
    "netgear": "router",
    "tp-link": "router",
    "linksys": "router",
    "asus": "router",
    "d-link": "router",
    "ubiquiti": "access_point",
    "mikrotik": "router",
    "juniper": "router",
    "aruba": "access_point",
    "ruckus": "access_point",
    "fortinet": "router",
    "palo alto": "router",
    "sonicwall": "router",
    "watchguard": "router",
    "zyxel": "router",
    "draytek": "router",

    # Servers/Compute
    "dell": "server",
    "hp": "server",
    "hewlett packard": "server",
    "lenovo": "server",
    "supermicro": "server",
    "vmware": "server",

    # Smart Home / IoT
    "amazon": "smart_home",
    "ring": "camera",
    "nest": "smart_home",
    "philips": "smart_home",
    "sonos": "smart_home",
    "ecobee": "smart_home",
    "wemo": "smart_home",
    "tuya": "iot",
    "shelly": "iot",
    "tasmota": "iot",
    "espressif": "iot",
    "raspberry": "server",

    # Gaming
    "sony": "gaming",
    "nintendo": "gaming",
    "microsoft": "gaming",
    "xbox": "gaming",
    "playstation": "gaming",
    "valve": "gaming",

    # TVs
    "roku": "tv",
    "vizio": "tv",
    "tcl": "tv",
    "hisense": "tv",
    "chromecast": "tv",
    "fire tv": "tv",
    "apple tv": "tv",

    # Printers
    "brother": "printer",
    "canon": "printer",
    "epson": "printer",
    "xerox": "printer",
    "ricoh": "printer",
    "kyocera": "printer",
    "lexmark": "printer",

    # NAS
    "synology": "nas",
    "qnap": "nas",
    "western digital": "nas",
    "seagate": "nas",
    "buffalo": "nas",
    "drobo": "nas",

    # Cameras
    "hikvision": "camera",
    "dahua": "camera",
    "axis": "camera",
    "wyze": "camera",
    "eufy": "camera",
    "reolink": "camera",
    "arlo": "camera",
    "blink": "camera",
}

# Hostname patterns for device type detection
HOSTNAME_PATTERNS = {
    # Phones
    "iphone": "phone",
    "ipad": "tablet",
    "android": "phone",
    "galaxy": "phone",
    "pixel": "phone",

    # Computers
    "macbook": "laptop",
    "imac": "desktop",
    "mac-mini": "desktop",
    "macpro": "desktop",
    "laptop": "laptop",
    "desktop": "desktop",
    "workstation": "desktop",
    "pc": "desktop",

    # Network
    "router": "router",
    "gateway": "router",
    "firewall": "router",
    "switch": "switch",
    "ap-": "access_point",
    "accesspoint": "access_point",
    "unifi": "access_point",

    # Servers
    "server": "server",
    "srv": "server",
    "nas": "nas",
    "plex": "server",
    "proxmox": "server",
    "esxi": "server",
    "docker": "server",
    "kubernetes": "server",
    "k8s": "server",
    "pi": "server",
    "raspberry": "server",

    # Smart Home
    "echo": "smart_home",
    "alexa": "smart_home",
    "google-home": "smart_home",
    "nest": "smart_home",
    "hue": "smart_home",
    "sonos": "smart_home",
    "homepod": "smart_home",

    # Entertainment
    "tv": "tv",
    "roku": "tv",
    "chromecast": "tv",
    "firetv": "tv",
    "appletv": "tv",
    "shield": "tv",
    "playstation": "gaming",
    "xbox": "gaming",
    "nintendo": "gaming",
    "ps4": "gaming",
    "ps5": "gaming",

    # Printers
    "printer": "printer",
    "print": "printer",
    "laserjet": "printer",
    "deskjet": "printer",
    "officejet": "printer",

    # Cameras
    "camera": "camera",
    "cam": "camera",
    "ipcam": "camera",
    "dvr": "camera",
    "nvr": "camera",
}

# OS patterns for device type detection
OS_PATTERNS = {
    "ios": "phone",
    "iphone": "phone",
    "ipad": "tablet",
    "android": "phone",
    "windows phone": "phone",
    "windows server": "server",
    "windows": "desktop",
    "macos": "desktop",
    "mac os": "desktop",
    "linux": "server",
    "ubuntu": "server",
    "debian": "server",
    "centos": "server",
    "red hat": "server",
    "freebsd": "server",
    "openwrt": "router",
    "routeros": "router",
    "junos": "router",
    "ios-xe": "router",
    "nx-os": "switch",
    "freenas": "nas",
    "truenas": "nas",
    "synology": "nas",
    "pfsense": "router",
    "opnsense": "router",
    "proxmox": "server",
    "esxi": "server",
    "vmware": "server",
    "playstation": "gaming",
    "xbox": "gaming",
    "nintendo": "gaming",
    "tizen": "tv",
    "webos": "tv",
    "roku": "tv",
    "fire os": "tv",
    "tvos": "tv",
}

# Port-based hints (less reliable, used as fallback)
PORT_HINTS = {
    # Server ports
    (22, 80, 443): "server",
    (22,): "server",
    (3389,): "desktop",  # RDP suggests Windows desktop
    (5900, 5901): "desktop",  # VNC
    (8080, 8443): "server",
    (9000, 9090): "server",

    # Printer ports
    (515, 631, 9100): "printer",
    (9100,): "printer",
    (631,): "printer",

    # NAS ports
    (5000, 5001): "nas",  # Synology
    (8080, 443, 22): "nas",

    # Smart home
    (8123,): "smart_home",  # Home Assistant
    (1883,): "iot",  # MQTT

    # Media
    (32400,): "server",  # Plex
    (8096,): "server",  # Jellyfin
}


def detect_device_type(
    vendor: Optional[str] = None,
    hostname: Optional[str] = None,
    os_name: Optional[str] = None,
    device_type: Optional[str] = None,
    ports: Optional[List[int]] = None,
    mac_address: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> str:
    """
    Detect device type based on available information.

    Returns the device type key (e.g., 'router', 'phone', 'server').
    Priority: explicit device_type > vendor > hostname > OS > ports > IP hints
    """
    # If device_type is already set and valid, use it
    if device_type and device_type.lower() in DEVICE_TYPES:
        return device_type.lower()

    # Check if IP suggests a gateway (common gateway IPs)
    if ip_address:
        if ip_address.endswith(".1") or ip_address.endswith(".254"):
            # Could be a router, but check other hints first
            pass

    # Check vendor
    if vendor:
        vendor_lower = vendor.lower()
        for pattern, dtype in VENDOR_PATTERNS.items():
            if pattern in vendor_lower:
                return dtype

    # Check hostname
    if hostname:
        hostname_lower = hostname.lower()
        for pattern, dtype in HOSTNAME_PATTERNS.items():
            if pattern in hostname_lower:
                return dtype

    # Check OS
    if os_name:
        os_lower = os_name.lower()
        for pattern, dtype in OS_PATTERNS.items():
            if pattern in os_lower:
                return dtype

    # Check ports (least reliable)
    if ports:
        port_set = set(ports)
        for port_tuple, dtype in PORT_HINTS.items():
            if set(port_tuple).issubset(port_set):
                return dtype

    # Gateway IP hint (fallback)
    if ip_address and (ip_address.endswith(".1") or ip_address.endswith(".254")):
        return "router"

    return "unknown"


def get_device_icon_info(device_type: str) -> Dict[str, str]:
    """Get icon info for a device type."""
    return DEVICE_TYPES.get(device_type, DEVICE_TYPES["unknown"])


def detect_and_get_icon(
    vendor: Optional[str] = None,
    hostname: Optional[str] = None,
    os_name: Optional[str] = None,
    device_type: Optional[str] = None,
    ports: Optional[List[int]] = None,
    mac_address: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Detect device type and return icon information.

    Returns dict with:
    - type: device type key
    - label: human-readable label
    - icon: icon identifier
    """
    dtype = detect_device_type(
        vendor=vendor,
        hostname=hostname,
        os_name=os_name,
        device_type=device_type,
        ports=ports,
        mac_address=mac_address,
        ip_address=ip_address,
    )
    info = get_device_icon_info(dtype)
    return {
        "type": dtype,
        "label": info["label"],
        "icon": info["icon"],
    }
