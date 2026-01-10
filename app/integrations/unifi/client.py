"""UniFi Network Controller API Client"""

import httpx
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

from app.integrations.unifi.models import UniFiClient, UniFiDevice, ConnectionType
from app.integrations.unifi.exceptions import (
    UniFiAuthenticationError,
    UniFiConnectionError,
    UniFiAPIError,
)

logger = logging.getLogger(__name__)


class UniFiAPIClient:
    """Client for UniFi Network Controller API"""

    def __init__(
        self,
        controller_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        site_id: str = "default",
        controller_type: str = "self_hosted",
        verify_ssl: bool = False,
        cache_seconds: int = 60,
        include_offline: bool = False,
    ):
        self.controller_url = controller_url.rstrip('/')
        self.username = username
        self.password = password
        self.api_key = api_key
        self.site_id = site_id
        self.controller_type = controller_type
        self.verify_ssl = verify_ssl
        self.cache_seconds = cache_seconds
        self.include_offline = include_offline

        self._session: Optional[httpx.AsyncClient] = None
        self._cookies: Dict[str, str] = {}
        self._csrf_token: Optional[str] = None
        self._authenticated = False
        self._last_auth: Optional[datetime] = None

        # Cache
        self._client_cache: Dict[str, UniFiClient] = {}
        self._cache_time: Optional[datetime] = None

    @property
    def base_url(self) -> str:
        """Get the base URL for API calls"""
        if self.controller_type == "udm":
            return f"{self.controller_url}/proxy/network"
        return self.controller_url

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
        """Authenticate with the UniFi controller"""
        if self.api_key:
            return await self._connect_api_key()
        return await self._connect_credentials()

    async def _connect_credentials(self) -> bool:
        """Authenticate using username/password"""
        session = await self._get_session()

        # Determine login endpoint based on controller type
        if self.controller_type == "udm":
            login_url = f"{self.controller_url}/api/auth/login"
        else:
            login_url = f"{self.base_url}/api/login"

        payload = {
            "username": self.username,
            "password": self.password,
            "remember": True,
        }

        try:
            response = await session.post(login_url, json=payload)

            if response.status_code == 200:
                self._cookies = dict(response.cookies)
                self._authenticated = True
                self._last_auth = datetime.utcnow()

                # Extract CSRF token if present
                csrf = response.headers.get("X-CSRF-Token")
                if csrf:
                    self._csrf_token = csrf

                logger.info("Successfully authenticated with UniFi controller")
                return True
            else:
                error_detail = ""
                try:
                    error_data = response.json()
                    error_detail = error_data.get("message", "")
                except Exception:
                    error_detail = response.text[:100]
                raise UniFiAuthenticationError(
                    f"Login failed (HTTP {response.status_code}): {error_detail}"
                )

        except httpx.RequestError as e:
            raise UniFiConnectionError(f"Connection failed: {str(e)}")

    async def _connect_api_key(self) -> bool:
        """Authenticate using API key (read-only)"""
        session = await self._get_session()

        headers = {"X-API-Key": self.api_key}
        url = f"{self.base_url}/api/s/{self.site_id}/stat/health"

        try:
            response = await session.get(url, headers=headers)
            if response.status_code == 200:
                self._authenticated = True
                self._last_auth = datetime.utcnow()
                logger.info("Successfully authenticated with UniFi API key")
                return True
            else:
                raise UniFiAuthenticationError(
                    f"API key validation failed (HTTP {response.status_code})"
                )
        except httpx.RequestError as e:
            raise UniFiConnectionError(f"Connection failed: {str(e)}")

    async def disconnect(self) -> None:
        """Close session and logout"""
        if self._session:
            # Logout if using session auth
            if self._authenticated and not self.api_key:
                try:
                    await self._session.post(f"{self.base_url}/api/logout")
                except Exception:
                    pass

            await self._session.aclose()
            self._session = None
            self._authenticated = False
            self._cookies = {}
            self._csrf_token = None

    async def _api_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
    ) -> Any:
        """Make an authenticated API request"""
        if not self._authenticated:
            await self.connect()

        session = await self._get_session()
        url = f"{self.base_url}/api/s/{self.site_id}/{endpoint}"

        headers = {}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        if self._csrf_token:
            headers["X-CSRF-Token"] = self._csrf_token

        try:
            if method.upper() == "GET":
                response = await session.get(
                    url, headers=headers, cookies=self._cookies
                )
            else:
                response = await session.request(
                    method, url, json=data, headers=headers, cookies=self._cookies
                )

            if response.status_code == 401:
                # Re-authenticate and retry
                self._authenticated = False
                await self.connect()
                return await self._api_request(method, endpoint, data)

            if response.status_code >= 400:
                raise UniFiAPIError(
                    f"API request failed (HTTP {response.status_code}): {endpoint}"
                )

            result = response.json()

            # UniFi API wraps data in a 'data' key
            if isinstance(result, dict) and "data" in result:
                return result["data"]
            return result

        except httpx.RequestError as e:
            raise UniFiAPIError(f"API request failed: {str(e)}")

    def _is_cache_valid(self) -> bool:
        """Check if client cache is still valid"""
        if not self._cache_time:
            return False
        age = (datetime.utcnow() - self._cache_time).total_seconds()
        return age < self.cache_seconds

    async def get_clients(self, force_refresh: bool = False) -> List[UniFiClient]:
        """Get all clients from the controller"""
        # Check cache first
        if not force_refresh and self._is_cache_valid():
            return list(self._client_cache.values())

        # Fetch active clients
        clients_data = await self._api_request("GET", "stat/sta")

        # Optionally fetch known/configured clients (includes offline)
        if self.include_offline:
            try:
                known_data = await self._api_request("GET", "rest/user")
                # Merge known clients that aren't in active list
                known_macs = {c.get("mac", "").upper() for c in clients_data}
                for user in known_data:
                    if user.get("mac", "").upper() not in known_macs:
                        user["_offline"] = True
                        clients_data.append(user)
            except UniFiAPIError:
                logger.warning("Failed to fetch offline clients")

        clients = [self._parse_client(c) for c in clients_data]

        # Update cache
        self._client_cache = {c.mac: c for c in clients}
        self._cache_time = datetime.utcnow()

        return clients

    async def get_client_by_mac(self, mac: str) -> Optional[UniFiClient]:
        """Get a specific client by MAC address"""
        mac = mac.upper().replace("-", ":")

        # Try cache first
        if self._is_cache_valid() and mac in self._client_cache:
            return self._client_cache[mac]

        # Fetch fresh data
        await self.get_clients()
        return self._client_cache.get(mac)

    def _parse_client(self, data: Dict[str, Any]) -> UniFiClient:
        """Parse raw API data into UniFiClient model"""
        mac = data.get("mac", "").upper()

        # Determine connection type
        is_wired = data.get("is_wired", False)
        connection_type = ConnectionType.WIRED if is_wired else ConnectionType.WIRELESS

        # Parse timestamps
        last_seen = None
        first_seen = None
        if "last_seen" in data:
            try:
                last_seen = datetime.fromtimestamp(data["last_seen"])
            except (ValueError, TypeError):
                pass
        if "first_seen" in data:
            try:
                first_seen = datetime.fromtimestamp(data["first_seen"])
            except (ValueError, TypeError):
                pass

        return UniFiClient(
            mac=mac,
            ip=data.get("ip"),
            hostname=data.get("hostname"),
            name=data.get("name"),
            connection_type=connection_type,
            is_wired=is_wired,
            is_guest=data.get("is_guest", False),
            # Wireless info
            ssid=data.get("essid"),
            bssid=data.get("bssid"),
            channel=data.get("channel"),
            radio=data.get("radio"),
            signal=data.get("signal"),
            rssi=data.get("rssi"),
            noise=data.get("noise"),
            tx_rate=data.get("tx_rate"),
            rx_rate=data.get("rx_rate"),
            # Wired info
            switch_mac=data.get("sw_mac"),
            switch_port=data.get("sw_port"),
            # State
            is_online=not data.get("_offline", False),
            uptime=data.get("uptime"),
            last_seen=last_seen,
            first_seen=first_seen,
            # Traffic
            tx_bytes=data.get("tx_bytes", 0),
            rx_bytes=data.get("rx_bytes", 0),
            tx_packets=data.get("tx_packets", 0),
            rx_packets=data.get("rx_packets", 0),
            # Device info
            oui=data.get("oui"),
            fingerprint=data.get("fingerprint"),
            device_type=data.get("dev_cat_name"),
            # Network
            network=data.get("network"),
            network_id=data.get("network_id"),
            vlan=data.get("vlan"),
            raw_data=data,
        )

    async def get_site_health(self) -> List[Dict[str, Any]]:
        """Get site health information"""
        return await self._api_request("GET", "stat/health")

    async def get_devices(self) -> List[UniFiDevice]:
        """Get UniFi network devices (APs, switches, gateways)"""
        data = await self._api_request("GET", "stat/device")
        return [self._parse_device(d) for d in data]

    def _parse_device(self, data: Dict[str, Any]) -> UniFiDevice:
        """Parse UniFi device data"""
        return UniFiDevice(
            mac=data.get("mac", "").upper(),
            name=data.get("name", "Unknown"),
            model=data.get("model", "Unknown"),
            ip=data.get("ip"),
            version=data.get("version"),
            state=data.get("state", "unknown"),
            clients_count=data.get("num_sta", 0),
            type=data.get("type", "unknown"),
        )
