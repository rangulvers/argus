"""UniFi Network Integration

Integrates with UniFi Network Controller to enrich device data with
connection information (wired/wireless, SSID, signal strength, traffic stats).
"""

from app.integrations.unifi.enricher import UniFiEnricher
from app.integrations.unifi.client import UniFiAPIClient
from app.integrations.unifi.models import UniFiClient, ConnectionType
from app.integrations.unifi.exceptions import (
    UniFiError,
    UniFiConnectionError,
    UniFiAuthenticationError,
    UniFiAPIError,
)

__all__ = [
    "UniFiEnricher",
    "UniFiAPIClient",
    "UniFiClient",
    "ConnectionType",
    "UniFiError",
    "UniFiConnectionError",
    "UniFiAuthenticationError",
    "UniFiAPIError",
]
