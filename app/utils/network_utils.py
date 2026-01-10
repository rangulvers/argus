"""Network utility functions for Argus"""

import socket
import logging
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)


def get_local_ip() -> Optional[str]:
    """Get the local IP address of this machine.

    Uses a socket connection to determine the primary network interface.
    """
    try:
        # Connect to a public DNS to determine our outbound IP
        # We don't actually send any data
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logger.warning(f"Could not determine local IP: {e}")
        return None


def ip_to_subnet(ip: str, prefix: int = 24) -> str:
    """Convert an IP address to a subnet in CIDR notation.

    Args:
        ip: IP address (e.g., "192.168.1.100")
        prefix: Subnet prefix length (default: 24 for /24)

    Returns:
        Subnet in CIDR notation (e.g., "192.168.1.0/24")
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return f"{ip}/{prefix}"

    if prefix == 24:
        # Class C - zero out last octet
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    elif prefix == 16:
        # Class B - zero out last two octets
        return f"{parts[0]}.{parts[1]}.0.0/16"
    elif prefix == 8:
        # Class A - zero out last three octets
        return f"{parts[0]}.0.0.0/8"
    else:
        # For other prefixes, just append
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/{prefix}"


def detect_subnet(prefix: int = 24) -> Optional[str]:
    """Detect the local network subnet.

    Args:
        prefix: Subnet prefix length (default: 24)

    Returns:
        Detected subnet in CIDR notation, or None if detection fails
    """
    ip = get_local_ip()
    if ip:
        return ip_to_subnet(ip, prefix)
    return None


def get_network_info() -> Dict:
    """Get information about the local network configuration.

    Returns:
        Dict with local_ip, suggested_subnet, and hostname
    """
    local_ip = get_local_ip()
    hostname = None

    try:
        hostname = socket.gethostname()
    except Exception:
        pass

    return {
        "local_ip": local_ip,
        "suggested_subnet": ip_to_subnet(local_ip, 24) if local_ip else None,
        "hostname": hostname
    }
