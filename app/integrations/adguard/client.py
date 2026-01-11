"""AdGuard Home API Client

REST API client for AdGuard Home DNS server.
"""

import httpx
import logging
import re
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from collections import defaultdict
import base64

from app.integrations.adguard.models import (
    DNSQuery,
    AdGuardClient,
    ClientDNSSummary,
    AdGuardStats,
    QueryResult,
    SUSPICIOUS_DOMAIN_PATTERNS,
    SUSPICIOUS_TLDS,
)
from app.integrations.adguard.exceptions import (
    AdGuardError,
    AdGuardAuthenticationError,
    AdGuardConnectionError,
    AdGuardAPIError,
)

logger = logging.getLogger(__name__)


class AdGuardAPIClient:
    """Client for AdGuard Home REST API"""

    def __init__(
        self,
        adguard_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = False,
        cache_seconds: int = 60,
    ):
        self.adguard_url = adguard_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.cache_seconds = cache_seconds

        self._session: Optional[httpx.AsyncClient] = None
        self._authenticated = False

        # Cache
        self._stats_cache: Optional[AdGuardStats] = None
        self._cache_time: Optional[datetime] = None

        # Compiled suspicious patterns
        self._suspicious_patterns = [
            re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_DOMAIN_PATTERNS
        ]

    def _get_auth_header(self) -> Dict[str, str]:
        """Get HTTP Basic Auth header"""
        if self.username and self.password:
            credentials = f"{self.username}:{self.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            return {"Authorization": f"Basic {encoded}"}
        return {}

    async def _get_session(self) -> httpx.AsyncClient:
        """Get or create HTTP session"""
        if self._session is None:
            self._session = httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=30.0,
                follow_redirects=True,
                headers=self._get_auth_header(),
            )
        return self._session

    async def connect(self) -> bool:
        """Connect and verify AdGuard Home is accessible"""
        session = await self._get_session()

        try:
            url = f"{self.adguard_url}/control/status"
            response = await session.get(url)

            if response.status_code == 401:
                raise AdGuardAuthenticationError(
                    "Authentication failed. Check username and password."
                )

            if response.status_code == 200:
                self._authenticated = True
                logger.info("Connected to AdGuard Home")
                return True
            else:
                raise AdGuardConnectionError(
                    f"Failed to connect (HTTP {response.status_code})"
                )

        except httpx.RequestError as e:
            raise AdGuardConnectionError(f"Connection failed: {str(e)}")

    async def disconnect(self) -> None:
        """Close session"""
        if self._session:
            await self._session.aclose()
            self._session = None
            self._authenticated = False

    def _is_cache_valid(self) -> bool:
        """Check if cache is still valid"""
        if not self._cache_time:
            return False
        age = (datetime.utcnow() - self._cache_time).total_seconds()
        return age < self.cache_seconds

    async def _api_request(
        self,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
    ) -> Any:
        """Make an API request to AdGuard Home"""
        if not self._authenticated:
            await self.connect()

        session = await self._get_session()
        url = f"{self.adguard_url}/control/{endpoint}"

        try:
            if method.upper() == "GET":
                response = await session.get(url, params=params)
            else:
                response = await session.request(method, url, params=params, json=data)

            if response.status_code == 401:
                raise AdGuardAuthenticationError("Session expired or invalid")

            if response.status_code >= 400:
                raise AdGuardAPIError(
                    f"API request failed (HTTP {response.status_code}): {endpoint}"
                )

            # Handle empty responses
            if not response.content:
                return {}

            return response.json()

        except httpx.RequestError as e:
            raise AdGuardAPIError(f"API request failed: {str(e)}")

    async def get_status(self) -> Dict[str, Any]:
        """Get AdGuard Home status"""
        return await self._api_request("status")

    async def get_stats(self, force_refresh: bool = False) -> AdGuardStats:
        """Get AdGuard Home statistics"""
        if not force_refresh and self._is_cache_valid() and self._stats_cache:
            return self._stats_cache

        data = await self._api_request("stats")

        stats = AdGuardStats(
            total_queries=data.get("num_dns_queries", 0),
            blocked_queries=data.get("num_blocked_filtering", 0),
            replaced_safebrowsing=data.get("num_replaced_safebrowsing", 0),
            replaced_parental=data.get("num_replaced_parental", 0),
            avg_processing_time=data.get("avg_processing_time", 0.0),
            num_dns_queries=data.get("num_dns_queries", 0),
            num_blocked_filtering=data.get("num_blocked_filtering", 0),
            num_replaced_safesearch=data.get("num_replaced_safesearch", 0),
        )

        self._stats_cache = stats
        self._cache_time = datetime.utcnow()
        return stats

    async def get_query_log(
        self,
        client_ip: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[DNSQuery]:
        """Get query log, optionally filtered by client IP"""
        params = {
            "limit": limit,
            "offset": offset,
        }

        # AdGuard Home uses "search" parameter for client filtering
        if client_ip:
            params["search"] = client_ip

        data = await self._api_request("querylog", params=params)
        queries = []

        for entry in data.get("data", []):
            result = self._parse_query_result(entry)
            timestamp = self._parse_timestamp(entry.get("time", ""))

            queries.append(DNSQuery(
                timestamp=timestamp,
                domain=entry.get("question", {}).get("name", ""),
                query_type=entry.get("question", {}).get("type", "A"),
                result=result,
                client_ip=entry.get("client", ""),
                client_name=entry.get("client_info", {}).get("name"),
                upstream=entry.get("upstream", ""),
                elapsed_ms=entry.get("elapsed_ms"),
                answer=self._format_answer(entry.get("answer", [])),
                rule=entry.get("rule"),
                filter_id=entry.get("filterId"),
            ))

        return queries

    async def get_clients(self) -> List[AdGuardClient]:
        """Get known clients with their stats"""
        # Get clients from AdGuard's client list
        clients_data = await self._api_request("clients")

        clients = []
        for client in clients_data.get("clients", []):
            # AdGuard stores clients by name with IPs array
            for ip in client.get("ids", []):
                # Skip non-IP identifiers (like MACs)
                if not self._is_ip(ip):
                    continue
                clients.append(AdGuardClient(
                    ip=ip,
                    name=client.get("name"),
                ))

        # Also get auto-discovered clients
        for client in clients_data.get("auto_clients", []):
            ip = client.get("ip", "")
            if ip:
                clients.append(AdGuardClient(
                    ip=ip,
                    name=client.get("name"),
                ))

        return clients

    async def get_dns_summary_for_client(
        self,
        client_ip: str,
        hours: int = 24,
    ) -> ClientDNSSummary:
        """Get DNS activity summary for a client"""
        # Get query log for this client
        queries = await self.get_query_log(client_ip=client_ip, limit=2000)

        # Filter to last N hours
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        queries = [q for q in queries if q.timestamp >= cutoff]

        # Calculate statistics
        total = len(queries)
        blocked = sum(1 for q in queries if q.result in [
            QueryResult.BLOCKED,
            QueryResult.BLOCKED_SAFEBROWSING,
            QueryResult.BLOCKED_PARENTAL,
        ])

        # Count domains
        domain_counts: Dict[str, int] = defaultdict(int)
        blocked_domain_counts: Dict[str, int] = defaultdict(int)
        query_types: Dict[str, int] = defaultdict(int)

        for q in queries:
            domain_counts[q.domain] += 1
            query_types[q.query_type] += 1

            if q.result in [
                QueryResult.BLOCKED,
                QueryResult.BLOCKED_SAFEBROWSING,
                QueryResult.BLOCKED_PARENTAL,
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

    def _parse_query_result(self, entry: Dict) -> QueryResult:
        """Parse query result from log entry"""
        reason = entry.get("reason", "").lower()

        if "filtered" in reason or "blocked" in reason:
            if "safebrowsing" in reason:
                return QueryResult.BLOCKED_SAFEBROWSING
            elif "parental" in reason:
                return QueryResult.BLOCKED_PARENTAL
            return QueryResult.BLOCKED
        elif "whitelisted" in reason:
            return QueryResult.WHITELISTED
        elif "rewritten" in reason:
            return QueryResult.REWRITTEN
        elif "safesearch" in reason:
            return QueryResult.SAFE_SEARCH

        return QueryResult.PROCESSED

    def _parse_timestamp(self, time_str: str) -> datetime:
        """Parse timestamp from AdGuard format"""
        try:
            # AdGuard uses ISO format with timezone
            if time_str:
                # Handle various formats
                time_str = time_str.replace("Z", "+00:00")
                return datetime.fromisoformat(time_str.replace("Z", ""))
        except (ValueError, TypeError):
            pass
        return datetime.utcnow()

    def _format_answer(self, answers: List[Dict]) -> Optional[str]:
        """Format DNS answer for display"""
        if not answers:
            return None
        values = [a.get("value", "") for a in answers[:3]]
        return ", ".join(v for v in values if v)

    def _is_ip(self, value: str) -> bool:
        """Check if value looks like an IP address"""
        parts = value.split(".")
        if len(parts) == 4:
            return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
        return ":" in value  # IPv6

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

        return list(set(suspicious))[:10]

    async def test_connection(self) -> Dict[str, Any]:
        """Test connection and return status info"""
        try:
            await self.connect()
            status = await self.get_status()
            stats = await self.get_stats()

            return {
                "connected": True,
                "version": status.get("version", "unknown"),
                "running": status.get("running", False),
                "protection_enabled": status.get("protection_enabled", False),
                "total_queries": stats.total_queries,
                "blocked_queries": stats.blocked_queries,
            }
        except AdGuardError as e:
            return {
                "connected": False,
                "error": str(e),
            }
