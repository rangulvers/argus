"""AdGuard Home Integration

Integrates with AdGuard Home DNS server to enrich device data with
DNS query information (domains contacted, blocked queries, suspicious activity).
"""

from app.integrations.adguard.enricher import AdGuardEnricher
from app.integrations.adguard.client import AdGuardAPIClient
from app.integrations.adguard.models import (
    DNSQuery,
    AdGuardClient,
    ClientDNSSummary,
    AdGuardStats,
    QueryResult,
)
from app.integrations.adguard.exceptions import (
    AdGuardError,
    AdGuardConnectionError,
    AdGuardAuthenticationError,
    AdGuardAPIError,
)

__all__ = [
    "AdGuardEnricher",
    "AdGuardAPIClient",
    "DNSQuery",
    "AdGuardClient",
    "ClientDNSSummary",
    "AdGuardStats",
    "QueryResult",
    "AdGuardError",
    "AdGuardConnectionError",
    "AdGuardAuthenticationError",
    "AdGuardAPIError",
]
