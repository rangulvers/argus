"""Base classes for Argus integrations"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum
from datetime import datetime


class IntegrationStatus(Enum):
    """Status of an integration connection"""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    DISABLED = "disabled"


@dataclass
class IntegrationHealth:
    """Health status for an integration"""
    status: IntegrationStatus
    last_check: Optional[datetime] = None
    last_successful_sync: Optional[datetime] = None
    error_message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class BaseIntegration(ABC):
    """Abstract base class for external integrations"""

    # Integration metadata - override in subclasses
    name: str = "base"
    display_name: str = "Base Integration"
    description: str = "Base integration class"
    icon: str = "plug"

    def __init__(self, config: Any):
        self.config = config
        self._connected = False
        self._last_error: Optional[str] = None

    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to the external service"""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the external service"""
        pass

    @abstractmethod
    async def test_connection(self) -> IntegrationHealth:
        """Test if the connection is working"""
        pass

    @abstractmethod
    async def get_data(self) -> Dict[str, Any]:
        """Retrieve data from the external service"""
        pass

    @property
    def is_enabled(self) -> bool:
        """Check if integration is enabled in config"""
        return getattr(self.config, 'enabled', False)

    @property
    def is_connected(self) -> bool:
        """Check if currently connected"""
        return self._connected


class DeviceEnricherIntegration(BaseIntegration):
    """Base class for integrations that enrich device data"""

    @abstractmethod
    async def enrich_device(self, device_mac: str, device_ip: str) -> Dict[str, Any]:
        """
        Enrich a single device with data from this integration.

        Args:
            device_mac: MAC address of the device
            device_ip: IP address of the device

        Returns:
            Dict of enrichment data to merge into device record
        """
        pass

    @abstractmethod
    async def enrich_devices_batch(
        self,
        devices: List[Dict[str, str]]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Batch enrich multiple devices.

        Args:
            devices: List of dicts with 'mac' and 'ip' keys

        Returns:
            Dict mapping MAC addresses to enrichment data
        """
        pass
