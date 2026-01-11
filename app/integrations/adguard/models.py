"""AdGuard Home data models"""

from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from datetime import datetime
from enum import Enum


class QueryResult(str, Enum):
    """DNS query result status"""
    PROCESSED = "processed"  # Normal query, forwarded/cached
    BLOCKED = "blocked"  # Blocked by filter
    BLOCKED_SAFEBROWSING = "blocked_safebrowsing"
    BLOCKED_PARENTAL = "blocked_parental"
    WHITELISTED = "whitelisted"
    REWRITTEN = "rewritten"
    SAFE_SEARCH = "safe_search"
    UNKNOWN = "unknown"


@dataclass
class DNSQuery:
    """Represents a single DNS query from AdGuard"""
    timestamp: datetime
    domain: str
    query_type: str  # A, AAAA, CNAME, PTR, etc.
    result: QueryResult
    client_ip: str
    client_name: Optional[str] = None
    upstream: Optional[str] = None
    elapsed_ms: Optional[float] = None
    answer: Optional[str] = None
    rule: Optional[str] = None  # Blocking rule if blocked
    filter_id: Optional[int] = None


@dataclass
class AdGuardClient:
    """Represents a client known to AdGuard Home"""
    ip: str
    name: Optional[str] = None
    mac: Optional[str] = None
    total_queries: int = 0
    blocked_queries: int = 0

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
    query_types: dict = field(default_factory=dict)
    last_query: Optional[datetime] = None

    @property
    def blocked_percentage(self) -> float:
        """Calculate percentage of blocked queries"""
        if self.total_queries_24h == 0:
            return 0.0
        return (self.blocked_queries_24h / self.total_queries_24h) * 100


@dataclass
class AdGuardStats:
    """Global AdGuard Home statistics"""
    total_queries: int = 0
    blocked_queries: int = 0
    replaced_safebrowsing: int = 0
    replaced_parental: int = 0
    avg_processing_time: float = 0.0
    num_dns_queries: int = 0
    num_blocked_filtering: int = 0
    num_replaced_safesearch: int = 0


# Suspicious domain patterns (shared with Pi-hole)
SUSPICIOUS_DOMAIN_PATTERNS = [
    r".*\.onion\..*",
    r".*\.tor2web\..*",
    r".*dyndns\..*",
    r".*no-ip\..*",
    r"^[a-z0-9]{32,}\.",
    r".*coinhive\..*",
    r".*cryptoloot\..*",
    r".*minero\..*",
    r".*coin-hive\..*",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".work", ".click", ".gq", ".cf", ".tk", ".ml", ".ga",
    ".download", ".stream", ".racing", ".win", ".bid", ".loan",
]
