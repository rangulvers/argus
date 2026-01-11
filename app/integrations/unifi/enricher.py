"""UniFi Device Enricher

Enriches Argus device records with data from UniFi Network Controller.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.integrations.base import (
    DeviceEnricherIntegration,
    IntegrationHealth,
    IntegrationStatus,
)
from app.integrations.unifi.client import UniFiAPIClient
from app.integrations.unifi.models import UniFiClient
from app.integrations.unifi.exceptions import UniFiError

logger = logging.getLogger(__name__)


class UniFiEnricher(DeviceEnricherIntegration):
    """Enriches Argus devices with UniFi client data"""

    name = "unifi"
    display_name = "UniFi Network"
    description = "Enrich devices with connection data from UniFi Network Controller"
    icon = "wifi"

    def __init__(
        self,
        enabled: bool = False,
        controller_url: str = "",
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        site_id: str = "default",
        controller_type: str = "self_hosted",
        verify_ssl: bool = False,
        cache_seconds: int = 60,
        sync_on_scan: bool = True,
        include_offline_clients: bool = False,
    ):
        # Store config as object-like
        class Config:
            pass

        self.config = Config()
        self.config.enabled = enabled
        self.config.controller_url = controller_url
        self.config.username = username
        self.config.password = password
        self.config.api_key = api_key
        self.config.site_id = site_id
        self.config.controller_type = controller_type
        self.config.verify_ssl = verify_ssl
        self.config.cache_seconds = cache_seconds
        self.config.sync_on_scan = sync_on_scan
        self.config.include_offline_clients = include_offline_clients

        self._connected = False
        self._last_error: Optional[str] = None
        self._last_health_check: Optional[datetime] = None
        self._last_sync: Optional[datetime] = None

        # Create API client
        self.client = UniFiAPIClient(
            controller_url=controller_url,
            username=username,
            password=password,
            api_key=api_key,
            site_id=site_id,
            controller_type=controller_type,
            verify_ssl=verify_ssl,
            cache_seconds=cache_seconds,
            include_offline=include_offline_clients,
        )

    async def connect(self) -> bool:
        """Connect to UniFi controller"""
        try:
            result = await self.client.connect()
            self._connected = result
            self._last_error = None
            return result
        except UniFiError as e:
            self._last_error = str(e)
            self._connected = False
            return False

    async def disconnect(self) -> None:
        """Disconnect from UniFi controller"""
        await self.client.disconnect()
        self._connected = False

    async def test_connection(self) -> IntegrationHealth:
        """Test connection to UniFi controller"""
        self._last_health_check = datetime.utcnow()

        if not self.is_enabled:
            return IntegrationHealth(
                status=IntegrationStatus.DISABLED,
                last_check=self._last_health_check,
                last_successful_sync=self._last_sync,
            )

        try:
            logger.info(f"Testing UniFi connection to {self.config.controller_url}")
            await self.connect()
            health_data = await self.client.get_site_health()

            # Count clients from health data
            num_clients = 0
            for subsystem in health_data:
                if "num_sta" in subsystem:
                    num_clients += subsystem.get("num_sta", 0)

            return IntegrationHealth(
                status=IntegrationStatus.CONNECTED,
                last_check=self._last_health_check,
                last_successful_sync=self._last_sync,
                details={
                    "clients": num_clients,
                    "controller_url": self.config.controller_url,
                    "site_id": self.config.site_id,
                },
            )
        except UniFiError as e:
            logger.error(f"UniFi connection test failed: {e}")
            return IntegrationHealth(
                status=IntegrationStatus.ERROR,
                last_check=self._last_health_check,
                last_successful_sync=self._last_sync,
                error_message=str(e),
            )
        except Exception as e:
            logger.error(f"UniFi connection test failed with unexpected error: {e}")
            return IntegrationHealth(
                status=IntegrationStatus.ERROR,
                last_check=self._last_health_check,
                last_successful_sync=self._last_sync,
                error_message=f"Unexpected error: {str(e)}",
            )

    async def get_data(self) -> Dict[str, Any]:
        """Get all UniFi client data"""
        clients = await self.client.get_clients()
        self._last_sync = datetime.utcnow()

        return {
            "clients": [self._client_to_dict(c) for c in clients],
            "count": len(clients),
            "fetched_at": self._last_sync.isoformat(),
        }

    async def enrich_device(self, device_mac: str, device_ip: str) -> Dict[str, Any]:
        """Enrich a single device with UniFi data"""
        if not self.is_enabled:
            return {}

        try:
            if not self._connected:
                await self.connect()

            unifi_client = await self.client.get_client_by_mac(device_mac)

            if not unifi_client:
                return {}

            return self._build_enrichment_data(unifi_client)

        except UniFiError as e:
            logger.warning(f"Failed to enrich device {device_mac}: {e}")
            return {}

    async def enrich_devices_batch(
        self,
        devices: List[Dict[str, str]],
    ) -> Dict[str, Dict[str, Any]]:
        """Batch enrich multiple devices.

        Returns a dict with two sub-dicts:
        - 'by_mac': enrichment data keyed by normalized MAC address
        - 'by_ip': enrichment data keyed by IP address (fallback when MAC unavailable)
        """
        if not self.is_enabled:
            return {"by_mac": {}, "by_ip": {}}

        try:
            if not self._connected:
                await self.connect()

            # Fetch all clients once
            clients = await self.client.get_clients()

            # Normalize MAC addresses consistently (uppercase, colons)
            def normalize_mac(mac: str) -> str:
                return mac.upper().replace("-", ":") if mac else ""

            # Build lookup maps by both MAC and IP
            client_by_mac = {normalize_mac(c.mac): c for c in clients if c.mac}
            client_by_ip = {c.ip: c for c in clients if c.ip}

            logger.debug(f"UniFi has {len(client_by_mac)} clients by MAC, {len(client_by_ip)} by IP")

            result_by_mac = {}
            result_by_ip = {}

            for device in devices:
                mac = normalize_mac(device.get("mac", ""))
                ip = device.get("ip", "")

                # Try MAC first (more reliable)
                if mac and mac in client_by_mac:
                    logger.debug(f"Matched device by MAC: {mac}")
                    result_by_mac[mac] = self._build_enrichment_data(client_by_mac[mac])
                # Fallback to IP matching
                elif ip and ip in client_by_ip:
                    logger.debug(f"Matched device by IP: {ip}")
                    result_by_ip[ip] = self._build_enrichment_data(client_by_ip[ip])

            self._last_sync = datetime.utcnow()
            logger.info(f"Enrichment: {len(result_by_mac)} by MAC, {len(result_by_ip)} by IP")
            return {"by_mac": result_by_mac, "by_ip": result_by_ip}

        except UniFiError as e:
            logger.warning(f"Failed to batch enrich devices: {e}")
            return {"by_mac": {}, "by_ip": {}}

    def _build_enrichment_data(self, client: UniFiClient) -> Dict[str, Any]:
        """Build enrichment data dict from UniFi client"""
        data: Dict[str, Any] = {
            "connection_type": client.connection_type.value,
            "is_online": client.is_online,
            "is_guest": client.is_guest,
        }

        # Wireless-specific data
        if not client.is_wired and client.ssid:
            data["wireless"] = {
                "ssid": client.ssid,
                "signal": client.signal,
                "rssi": client.rssi,
                "channel": client.channel,
                "radio": client.radio,
                "tx_rate": client.tx_rate,
                "rx_rate": client.rx_rate,
            }

        # Wired-specific data
        if client.is_wired and (client.switch_mac or client.switch_port):
            data["wired"] = {
                "switch_mac": client.switch_mac,
                "switch_port": client.switch_port,
            }

        # Traffic stats
        if client.tx_bytes or client.rx_bytes:
            data["traffic"] = {
                "tx_bytes": client.tx_bytes,
                "rx_bytes": client.rx_bytes,
                "tx_packets": client.tx_packets,
                "rx_packets": client.rx_packets,
            }

        # Uptime
        if client.uptime:
            data["uptime_seconds"] = client.uptime

        # Network info
        if client.network or client.vlan:
            data["network"] = {
                "name": client.network,
                "vlan": client.vlan,
            }

        # UniFi's device type guess
        if client.device_type:
            data["device_type"] = client.device_type

        # User-assigned name in UniFi
        if client.name:
            data["unifi_name"] = client.name

        return {"unifi": data}

    def _client_to_dict(self, client: UniFiClient) -> Dict[str, Any]:
        """Convert UniFi client to dictionary for API response"""
        return {
            "mac": client.mac,
            "ip": client.ip,
            "hostname": client.hostname,
            "name": client.name,
            "connection_type": client.connection_type.value,
            "is_wired": client.is_wired,
            "is_online": client.is_online,
            "is_guest": client.is_guest,
            "ssid": client.ssid,
            "signal": client.signal,
            "channel": client.channel,
            "uptime": client.uptime,
            "tx_bytes": client.tx_bytes,
            "rx_bytes": client.rx_bytes,
            "network": client.network,
            "vlan": client.vlan,
        }
