"""Pi-hole data models"""

from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from datetime import datetime
from enum import Enum


class QueryStatus(str, Enum):
    """DNS query status"""
    FORWARDED = "forwarded"
    BLOCKED = "blocked"
    CACHED = "cached"
    REGEX_BLOCKED = "regex_blocked"
    BLACKLIST_BLOCKED = "blacklist_blocked"
    EXTERNAL_BLOCKED = "external_blocked"
    UNKNOWN = "unknown"


class PiHoleVersion(str, Enum):
    """Pi-hole version for API compatibility"""
    V5 = "v5"
    V6 = "v6"
    UNKNOWN = "unknown"


@dataclass
class DNSQuery:
    """Represents a single DNS query"""
    timestamp: datetime
    domain: str
    query_type: str  # A, AAAA, CNAME, PTR, etc.
    status: QueryStatus
    client_ip: str
    upstream: Optional[str] = None
    reply_time: Optional[float] = None  # Response time in ms
    dnssec: Optional[str] = None


@dataclass
class PiHoleClient:
    """Represents a client known to Pi-hole"""
    ip: str
    name: Optional[str] = None  # Hostname from DHCP/hosts
    mac: Optional[str] = None  # MAC address if available
    total_queries: int = 0
    blocked_queries: int = 0
    last_seen: Optional[datetime] = None

    @property
    def blocked_percentage(self) -> float:
        """Calculate percentage of blocked queries"""
        if self.total_queries == 0:
            return 0.0
        return (self.blocked_queries / self.total_queries) * 100


@dataclass
class ClientDNSSummary:
    """DNS activity summary for a specific client"""
    client_ip: str
    total_queries_24h: int = 0
    blocked_queries_24h: int = 0
    unique_domains: int = 0
    top_domains: List[Tuple[str, int]] = field(default_factory=list)
    blocked_domains: List[Tuple[str, int]] = field(default_factory=list)
    suspicious_domains: List[str] = field(default_factory=list)
    query_types: dict = field(default_factory=dict)  # {"A": 500, "AAAA": 200, ...}
    last_query: Optional[datetime] = None

    @property
    def blocked_percentage(self) -> float:
        """Calculate percentage of blocked queries"""
        if self.total_queries_24h == 0:
            return 0.0
        return (self.blocked_queries_24h / self.total_queries_24h) * 100


@dataclass
class PiHoleStats:
    """Global Pi-hole statistics"""
    total_queries: int = 0
    queries_blocked: int = 0
    percent_blocked: float = 0.0
    domains_on_blocklist: int = 0
    unique_domains: int = 0
    queries_forwarded: int = 0
    queries_cached: int = 0
    clients_seen: int = 0
    status: str = "unknown"  # enabled, disabled


# Suspicious domain patterns for detection
SUSPICIOUS_DOMAIN_PATTERNS = [
    # Known malware/C2 patterns
    r".*\.onion\..*",
    r".*\.tor2web\..*",
    r".*dyndns\..*",
    r".*no-ip\..*",
    # High entropy subdomains (potential data exfiltration)
    r"^[a-z0-9]{32,}\.",
    # Cryptocurrency mining
    r".*coinhive\..*",
    r".*cryptoloot\..*",
    r".*minero\..*",
    r".*coin-hive\..*",
]

# Known suspicious TLDs
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".work", ".click", ".gq", ".cf", ".tk", ".ml", ".ga",
    ".download", ".stream", ".racing", ".win", ".bid", ".loan",
]
