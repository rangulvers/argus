"""Pi-hole API Client

Supports both Pi-hole v5 (PHP API) and v6 (REST API) with auto-detection.
"""

import httpx
import logging
import re
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from collections import defaultdict

from app.integrations.pihole.models import (
    DNSQuery,
    PiHoleClient,
    ClientDNSSummary,
    PiHoleStats,
    QueryStatus,
    PiHoleVersion,
    SUSPICIOUS_DOMAIN_PATTERNS,
    SUSPICIOUS_TLDS,
)
from app.integrations.pihole.exceptions import (
    PiHoleAuthenticationError,
    PiHoleConnectionError,
    PiHoleAPIError,
)

logger = logging.getLogger(__name__)


class PiHoleAPIClient:
    """Client for Pi-hole API (supports v5 and v6)"""

    def __init__(
        self,
        pihole_url: str,
        api_token: Optional[str] = None,
        verify_ssl: bool = False,
        cache_seconds: int = 60,
    ):
        self.pihole_url = pihole_url.rstrip("/")
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        self.cache_seconds = cache_seconds

        self._session: Optional[httpx.AsyncClient] = None
        self._version: PiHoleVersion = PiHoleVersion.UNKNOWN
        self._authenticated = False
        self._sid: Optional[str] = None  # v6 session ID

        # Cache
        self._stats_cache: Optional[PiHoleStats] = None
        self._clients_cache: List[PiHoleClient] = []
        self._cache_time: Optional[datetime] = None

        # Compiled suspicious patterns
        self._suspicious_patterns = [
            re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_DOMAIN_PATTERNS
        ]

    async def _get_session(self) -> httpx.AsyncClient:
        """Get or create HTTP session"""
        if self._session is None:
            self._session = httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=30.0,
                follow_redirects=True,
            )
        return self._session

    async def connect(self) -> bool:
        """Connect and detect Pi-hole version"""
        session = await self._get_session()

        # Try v6 API first
        try:
            v6_url = f"{self.pihole_url}/api/auth"
            if self.api_token:
                # v6 uses app password for auth
                response = await session.post(
                    v6_url,
                    json={"password": self.api_token},
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("session", {}).get("valid"):
                        self._version = PiHoleVersion.V6
                        self._sid = data.get("session", {}).get("sid")
                        self._authenticated = True
                        logger.info("Connected to Pi-hole v6 with authentication")
                        return True
            else:
                # Try unauthenticated v6 endpoint
                response = await session.get(f"{self.pihole_url}/api/info/version")
                if response.status_code == 200:
                    self._version = PiHoleVersion.V6
                    self._authenticated = True
                    logger.info("Connected to Pi-hole v6 (unauthenticated)")
                    return True
        except Exception as e:
            logger.debug(f"v6 API not available: {e}")

        # Try v5 API
        try:
            v5_url = f"{self.pihole_url}/admin/api.php"
            params = {"summaryRaw": ""}
            if self.api_token:
                params["auth"] = self.api_token

            response = await session.get(v5_url, params=params)
            if response.status_code == 200:
                data = response.json()
                if "domains_being_blocked" in data or "status" in data:
                    self._version = PiHoleVersion.V5
                    self._authenticated = True
                    logger.info("Connected to Pi-hole v5")
                    return True
        except Exception as e:
            logger.debug(f"v5 API not available: {e}")

        raise PiHoleConnectionError(
            f"Could not connect to Pi-hole at {self.pihole_url}. "
            "Check URL and API token."
        )

    async def disconnect(self) -> None:
        """Close session"""
        if self._session:
            # Logout from v6 if authenticated
            if self._version == PiHoleVersion.V6 and self._sid:
                try:
                    await self._session.delete(
                        f"{self.pihole_url}/api/auth",
                        headers={"sid": self._sid},
                    )
                except Exception:
                    pass

            await self._session.aclose()
            self._session = None
            self._authenticated = False
            self._sid = None

    def _is_cache_valid(self) -> bool:
        """Check if cache is still valid"""
        if not self._cache_time:
            return False
        age = (datetime.utcnow() - self._cache_time).total_seconds()
        return age < self.cache_seconds

    async def _v5_request(
        self,
        params: Dict[str, Any],
    ) -> Any:
        """Make a Pi-hole v5 API request"""
        session = await self._get_session()

        if self.api_token:
            params["auth"] = self.api_token

        url = f"{self.pihole_url}/admin/api.php"

        try:
            response = await session.get(url, params=params)
            if response.status_code != 200:
                raise PiHoleAPIError(
                    f"v5 API request failed (HTTP {response.status_code})"
                )
            return response.json()
        except httpx.RequestError as e:
            raise PiHoleAPIError(f"v5 API request failed: {e}")

    async def _v6_request(
        self,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
    ) -> Any:
        """Make a Pi-hole v6 API request"""
        session = await self._get_session()

        url = f"{self.pihole_url}/api/{endpoint}"
        headers = {}
        if self._sid:
            headers["sid"] = self._sid

        try:
            if method.upper() == "GET":
                response = await session.get(url, params=params, headers=headers)
            else:
                response = await session.request(
                    method, url, params=params, json=data, headers=headers
                )

            if response.status_code == 401:
                raise PiHoleAuthenticationError("Session expired or invalid")

            if response.status_code >= 400:
                raise PiHoleAPIError(
                    f"v6 API request failed (HTTP {response.status_code}): {endpoint}"
                )

            return response.json()
        except httpx.RequestError as e:
            raise PiHoleAPIError(f"v6 API request failed: {e}")

    async def get_stats(self, force_refresh: bool = False) -> PiHoleStats:
        """Get Pi-hole statistics"""
        if not force_refresh and self._is_cache_valid() and self._stats_cache:
            return self._stats_cache

        if not self._authenticated:
            await self.connect()

        if self._version == PiHoleVersion.V6:
            data = await self._v6_request("stats/summary")
            stats = PiHoleStats(
                total_queries=data.get("queries", {}).get("total", 0),
                queries_blocked=data.get("queries", {}).get("blocked", 0),
                percent_blocked=data.get("queries", {}).get("percent_blocked", 0),
                domains_on_blocklist=data.get("gravity", {}).get("domains_being_blocked", 0),
                unique_domains=data.get("queries", {}).get("unique_domains", 0),
                queries_forwarded=data.get("queries", {}).get("forwarded", 0),
                queries_cached=data.get("queries", {}).get("cached", 0),
                clients_seen=data.get("clients", {}).get("total", 0),
                status="enabled" if data.get("blocking", True) else "disabled",
            )
        else:
            data = await self._v5_request({"summaryRaw": ""})
            stats = PiHoleStats(
                total_queries=data.get("dns_queries_today", 0),
                queries_blocked=data.get("ads_blocked_today", 0),
                percent_blocked=data.get("ads_percentage_today", 0),
                domains_on_blocklist=data.get("domains_being_blocked", 0),
                unique_domains=data.get("unique_domains", 0),
                queries_forwarded=data.get("queries_forwarded", 0),
                queries_cached=data.get("queries_cached", 0),
                clients_seen=data.get("unique_clients", 0),
                status=data.get("status", "unknown"),
            )

        self._stats_cache = stats
        self._cache_time = datetime.utcnow()
        return stats

    async def get_clients(self, force_refresh: bool = False) -> List[PiHoleClient]:
        """Get all known Pi-hole clients"""
        if not force_refresh and self._is_cache_valid() and self._clients_cache:
            return self._clients_cache

        if not self._authenticated:
            await self.connect()

        clients = []

        if self._version == PiHoleVersion.V6:
            data = await self._v6_request("network/clients")
            for c in data.get("clients", []):
                clients.append(PiHoleClient(
                    ip=c.get("ip", ""),
                    name=c.get("name"),
                    mac=c.get("hwaddr"),
                    total_queries=c.get("count", 0),
                    blocked_queries=0,  # v6 doesn't provide per-client blocked count directly
                ))
        else:
            # v5 getQuerySources for client list
            data = await self._v5_request({"getQuerySources": "", "topClientsBlocked": ""})
            sources = data.get("top_sources", {})
            blocked = data.get("top_sources_blocked", {})

            for client_str, count in sources.items():
                # Format is "ip|hostname" or just "ip"
                parts = client_str.split("|")
                ip = parts[0]
                name = parts[1] if len(parts) > 1 else None
                blocked_count = blocked.get(client_str, 0)

                clients.append(PiHoleClient(
                    ip=ip,
                    name=name,
                    total_queries=count,
                    blocked_queries=blocked_count,
                ))

        self._clients_cache = clients
        self._cache_time = datetime.utcnow()
        return clients

    async def get_queries_for_client(
        self,
        client_ip: str,
        hours: int = 24,
        limit: int = 1000,
    ) -> List[DNSQuery]:
        """Get recent DNS queries for a specific client"""
        if not self._authenticated:
            await self.connect()

        queries = []
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=hours)

        if self._version == PiHoleVersion.V6:
            # v6 API with client filter
            params = {
                "client": client_ip,
                "from": int(cutoff.timestamp()),
                "until": int(now.timestamp()),
                "length": limit,
            }
            data = await self._v6_request("queries", params=params)

            for q in data.get("queries", []):
                status = self._parse_query_status_v6(q.get("status", 0))
                queries.append(DNSQuery(
                    timestamp=datetime.fromtimestamp(q.get("time", 0)),
                    domain=q.get("domain", ""),
                    query_type=q.get("type", "A"),
                    status=status,
                    client_ip=q.get("client", client_ip),
                    upstream=q.get("upstream"),
                    reply_time=q.get("reply", {}).get("time"),
                    dnssec=q.get("dnssec"),
                ))
        else:
            # v5 API - getAllQueries with client filter
            params = {
                "getAllQueries": limit,
                "client": client_ip,
            }
            data = await self._v5_request(params)

            for q in data.get("data", []):
                # v5 format: [timestamp, type, domain, client, status, ...]
                if len(q) >= 5:
                    ts = datetime.fromtimestamp(int(q[0]))
                    if ts < cutoff:
                        continue

                    status = self._parse_query_status_v5(int(q[4]))
                    queries.append(DNSQuery(
                        timestamp=ts,
                        domain=q[2],
                        query_type=q[1],
                        status=status,
                        client_ip=q[3],
                    ))

        return queries

    async def get_dns_summary_for_client(
        self,
        client_ip: str,
        hours: int = 24,
    ) -> ClientDNSSummary:
        """Get DNS activity summary for a client"""
        queries = await self.get_queries_for_client(client_ip, hours=hours)

        # Calculate statistics
        total = len(queries)
        blocked = sum(1 for q in queries if q.status in [
            QueryStatus.BLOCKED,
            QueryStatus.REGEX_BLOCKED,
            QueryStatus.BLACKLIST_BLOCKED,
            QueryStatus.EXTERNAL_BLOCKED,
        ])

        # Count domains
        domain_counts: Dict[str, int] = defaultdict(int)
        blocked_domain_counts: Dict[str, int] = defaultdict(int)
        query_types: Dict[str, int] = defaultdict(int)

        for q in queries:
            domain_counts[q.domain] += 1
            query_types[q.query_type] += 1

            if q.status in [
                QueryStatus.BLOCKED,
                QueryStatus.REGEX_BLOCKED,
                QueryStatus.BLACKLIST_BLOCKED,
                QueryStatus.EXTERNAL_BLOCKED,
            ]:
                blocked_domain_counts[q.domain] += 1

        # Sort by count
        top_domains = sorted(domain_counts.items(), key=lambda x: -x[1])[:20]
        blocked_domains = sorted(blocked_domain_counts.items(), key=lambda x: -x[1])[:20]

        # Detect suspicious domains
        suspicious = self._detect_suspicious_domains(list(domain_counts.keys()))

        last_query = max((q.timestamp for q in queries), default=None)

        return ClientDNSSummary(
            client_ip=client_ip,
            total_queries_24h=total,
            blocked_queries_24h=blocked,
            unique_domains=len(domain_counts),
            top_domains=top_domains,
            blocked_domains=blocked_domains,
            suspicious_domains=suspicious,
            query_types=dict(query_types),
            last_query=last_query,
        )

    def _parse_query_status_v5(self, status_code: int) -> QueryStatus:
        """Parse v5 query status code"""
        status_map = {
            1: QueryStatus.BLOCKED,  # Blocked (gravity)
            2: QueryStatus.FORWARDED,  # OK (forwarded)
            3: QueryStatus.CACHED,  # OK (cache)
            4: QueryStatus.REGEX_BLOCKED,  # Blocked (regex)
            5: QueryStatus.BLACKLIST_BLOCKED,  # Blocked (blacklist)
            6: QueryStatus.EXTERNAL_BLOCKED,  # Blocked (external)
        }
        return status_map.get(status_code, QueryStatus.UNKNOWN)

    def _parse_query_status_v6(self, status: Any) -> QueryStatus:
        """Parse v6 query status"""
        if isinstance(status, str):
            status_lower = status.lower()
            if "blocked" in status_lower:
                return QueryStatus.BLOCKED
            elif "forwarded" in status_lower:
                return QueryStatus.FORWARDED
            elif "cached" in status_lower:
                return QueryStatus.CACHED
        elif isinstance(status, int):
            return self._parse_query_status_v5(status)
        return QueryStatus.UNKNOWN

    def _detect_suspicious_domains(self, domains: List[str]) -> List[str]:
        """Detect potentially suspicious domains"""
        suspicious = []

        for domain in domains:
            # Check against suspicious TLDs
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    suspicious.append(domain)
                    break
            else:
                # Check against suspicious patterns
                for pattern in self._suspicious_patterns:
                    if pattern.match(domain):
                        suspicious.append(domain)
                        break

        return list(set(suspicious))[:10]  # Return max 10 unique

    async def test_connection(self) -> Dict[str, Any]:
        """Test connection and return status info"""
        try:
            await self.connect()
            stats = await self.get_stats()

            return {
                "connected": True,
                "version": self._version.value,
                "status": stats.status,
                "total_queries": stats.total_queries,
                "blocked_queries": stats.queries_blocked,
                "domains_on_blocklist": stats.domains_on_blocklist,
                "clients_seen": stats.clients_seen,
            }
        except PiHoleError as e:
            return {
                "connected": False,
                "error": str(e),
            }
