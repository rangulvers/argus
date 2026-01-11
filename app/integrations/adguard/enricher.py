"""AdGuard Home Device Enricher

Enriches Argus device records with DNS activity data from AdGuard Home.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.integrations.base import (
    DeviceEnricherIntegration,
    IntegrationHealth,
    IntegrationStatus,
)
from app.integrations.adguard.client import AdGuardAPIClient
from app.integrations.adguard.models import ClientDNSSummary
from app.integrations.adguard.exceptions import AdGuardError

logger = logging.getLogger(__name__)


class AdGuardEnricher(DeviceEnricherIntegration):
    """Enriches Argus devices with AdGuard Home DNS data"""

    name = "adguard"
    display_name = "AdGuard Home"
    description = "Enrich devices with DNS query data from AdGuard Home"
    icon = "shield"

    def __init__(
        self,
        enabled: bool = False,
        adguard_url: str = "",
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = False,
        cache_seconds: int = 60,
        sync_on_scan: bool = True,
    ):
        # Store config as object-like
        class Config:
            pass

        self.config = Config()
        self.config.enabled = enabled
        self.config.adguard_url = adguard_url
        self.config.username = username
        self.config.password = password
        self.config.verify_ssl = verify_ssl
        self.config.cache_seconds = cache_seconds
        self.config.sync_on_scan = sync_on_scan

        self._connected = False
        self._last_error: Optional[str] = None
        self._last_health_check: Optional[datetime] = None
        self._last_sync: Optional[datetime] = None

        # Create API client
        self.client = AdGuardAPIClient(
            adguard_url=adguard_url,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            cache_seconds=cache_seconds,
        )

    async def connect(self) -> bool:
        """Connect to AdGuard Home"""
        try:
            result = await self.client.connect()
            self._connected = result
            self._last_error = None
            return result
        except AdGuardError as e:
            self._last_error = str(e)
            self._connected = False
            return False

    async def disconnect(self) -> None:
        """Disconnect from AdGuard Home"""
        await self.client.disconnect()
        self._connected = False

    async def test_connection(self) -> IntegrationHealth:
        """Test connection to AdGuard Home"""
        self._last_health_check = datetime.utcnow()

        if not self.is_enabled:
            return IntegrationHealth(
                status=IntegrationStatus.DISABLED,
                last_check=self._last_health_check,
                last_successful_sync=self._last_sync,
            )

        try:
            logger.info(f"Testing AdGuard Home connection to {self.config.adguard_url}")
            test_result = await self.client.test_connection()

            if test_result.get("connected"):
                return IntegrationHealth(
                    status=IntegrationStatus.CONNECTED,
                    last_check=self._last_health_check,
                    last_successful_sync=self._last_sync,
                    details={
                        "version": test_result.get("version"),
                        "running": test_result.get("running"),
                        "protection_enabled": test_result.get("protection_enabled"),
                        "total_queries": test_result.get("total_queries"),
                        "blocked_queries": test_result.get("blocked_queries"),
                        "adguard_url": self.config.adguard_url,
                    },
                )
            else:
                return IntegrationHealth(
                    status=IntegrationStatus.ERROR,
                    last_check=self._last_health_check,
                    last_successful_sync=self._last_sync,
                    error_message=test_result.get("error", "Connection failed"),
                )
        except AdGuardError as e:
            logger.error(f"AdGuard Home connection test failed: {e}")
            return IntegrationHealth(
                status=IntegrationStatus.ERROR,
                last_check=self._last_health_check,
                last_successful_sync=self._last_sync,
                error_message=str(e),
            )
        except Exception as e:
            logger.error(f"AdGuard Home connection test failed with unexpected error: {e}")
            return IntegrationHealth(
                status=IntegrationStatus.ERROR,
                last_check=self._last_health_check,
                last_successful_sync=self._last_sync,
                error_message=f"Unexpected error: {str(e)}",
            )

    async def get_data(self) -> Dict[str, Any]:
        """Get all AdGuard Home data"""
        stats = await self.client.get_stats()
        clients = await self.client.get_clients()
        self._last_sync = datetime.utcnow()

        return {
            "stats": {
                "total_queries": stats.total_queries,
                "blocked_queries": stats.blocked_queries,
                "replaced_safebrowsing": stats.replaced_safebrowsing,
                "replaced_parental": stats.replaced_parental,
                "avg_processing_time": stats.avg_processing_time,
            },
            "clients": [
                {
                    "ip": c.ip,
                    "name": c.name,
                    "total_queries": c.total_queries,
                    "blocked_queries": c.blocked_queries,
                }
                for c in clients
            ],
            "fetched_at": self._last_sync.isoformat(),
        }

    async def enrich_device(self, device_mac: str, device_ip: str) -> Dict[str, Any]:
        """Enrich a single device with AdGuard Home DNS data"""
        if not self.is_enabled:
            return {}

        try:
            if not self._connected:
                await self.connect()

            # AdGuard Home tracks by IP
            summary = await self.client.get_dns_summary_for_client(device_ip)

            if summary.total_queries_24h == 0:
                return {}

            return self._build_enrichment_data(summary)

        except AdGuardError as e:
            logger.warning(f"Failed to enrich device {device_ip}: {e}")
            return {}

    async def enrich_devices_batch(
        self,
        devices: List[Dict[str, str]],
    ) -> Dict[str, Dict[str, Any]]:
        """Batch enrich multiple devices.

        Returns a dict with enrichment data keyed by IP address.
        AdGuard Home tracks clients by IP, so we use IP for matching.
        """
        if not self.is_enabled:
            return {"by_mac": {}, "by_ip": {}}

        try:
            if not self._connected:
                await self.connect()

            result_by_ip = {}

            for device in devices:
                ip = device.get("ip", "")
                if not ip:
                    continue

                try:
                    summary = await self.client.get_dns_summary_for_client(ip)
                    if summary.total_queries_24h > 0:
                        logger.debug(f"AdGuard: Enriching device {ip} with {summary.total_queries_24h} queries")
                        result_by_ip[ip] = self._build_enrichment_data(summary)
                except AdGuardError as e:
                    logger.warning(f"Failed to get DNS data for {ip}: {e}")

            self._last_sync = datetime.utcnow()
            logger.info(f"AdGuard Home enrichment: {len(result_by_ip)} devices enriched")

            return {"by_mac": {}, "by_ip": result_by_ip}

        except AdGuardError as e:
            logger.warning(f"Failed to batch enrich devices: {e}")
            return {"by_mac": {}, "by_ip": {}}

    def _build_enrichment_data(self, summary: ClientDNSSummary) -> Dict[str, Any]:
        """Build enrichment data dict from DNS summary"""
        dns_risk_score = self._calculate_dns_risk(summary)

        data: Dict[str, Any] = {
            "queries_24h": summary.total_queries_24h,
            "blocked_24h": summary.blocked_queries_24h,
            "blocked_percentage": round(summary.blocked_percentage, 1),
            "unique_domains": summary.unique_domains,
            "dns_risk_score": dns_risk_score,
        }

        # Top domains (limit to 10)
        if summary.top_domains:
            data["top_domains"] = [
                {"domain": d, "count": c} for d, c in summary.top_domains[:10]
            ]

        # Blocked domains (limit to 10)
        if summary.blocked_domains:
            data["blocked_domains"] = [
                {"domain": d, "count": c} for d, c in summary.blocked_domains[:10]
            ]

        # Suspicious domains
        if summary.suspicious_domains:
            data["suspicious_domains"] = summary.suspicious_domains

        # Query types breakdown
        if summary.query_types:
            data["query_types"] = summary.query_types

        # Last query time
        if summary.last_query:
            data["last_query"] = summary.last_query.isoformat()

        # Use "adguard" key to match the integration name
        return {"adguard": data}

    def _calculate_dns_risk(self, summary: ClientDNSSummary) -> int:
        """Calculate DNS behavior risk score 0-100"""
        score = 0

        # High blocked percentage might indicate malware
        if summary.blocked_percentage > 50:
            score += 30
        elif summary.blocked_percentage > 30:
            score += 15
        elif summary.blocked_percentage > 15:
            score += 5

        # Suspicious domains detected
        num_suspicious = len(summary.suspicious_domains)
        if num_suspicious > 0:
            score += min(num_suspicious * 15, 40)

        # Very high query count could indicate exfiltration
        if summary.total_queries_24h > 10000:
            score += 15
        elif summary.total_queries_24h > 5000:
            score += 5

        # High unique domain count could indicate DGA malware
        if summary.unique_domains > 1000:
            score += 20
        elif summary.unique_domains > 500:
            score += 10

        return min(score, 100)
