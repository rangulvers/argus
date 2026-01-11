"""Pi-hole Integration

Integrates with Pi-hole DNS sinkhole to enrich device data with
DNS query information (domains contacted, blocked queries, suspicious activity).
"""

from app.integrations.pihole.enricher import PiHoleEnricher
from app.integrations.pihole.client import PiHoleAPIClient
from app.integrations.pihole.models import (
    DNSQuery,
    PiHoleClient,
    ClientDNSSummary,
    PiHoleStats,
    QueryStatus,
    PiHoleVersion,
)
from app.integrations.pihole.exceptions import (
    PiHoleError,
    PiHoleConnectionError,
    PiHoleAuthenticationError,
    PiHoleAPIError,
)

__all__ = [
    "PiHoleEnricher",
    "PiHoleAPIClient",
    "DNSQuery",
    "PiHoleClient",
    "ClientDNSSummary",
    "PiHoleStats",
    "QueryStatus",
    "PiHoleVersion",
    "PiHoleError",
    "PiHoleConnectionError",
    "PiHoleAuthenticationError",
    "PiHoleAPIError",
]
