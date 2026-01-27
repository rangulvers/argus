"""Configuration management for Argus"""

from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import Optional, List, Any
import yaml
import os


class NetworkConfig(BaseSettings):
    """Network scanning configuration"""
    subnet: str = "192.168.1.0/24"
    scan_schedule: str = "0 2 * * 0"  # Cron format: 2 AM every Sunday
    scan_profile: str = "normal"  # quick, normal, intensive


class ScanningConfig(BaseSettings):
    """Scanning behavior configuration"""
    port_range: str = "1-1000"  # or "common" or "all"
    enable_os_detection: bool = True
    enable_service_detection: bool = True
    timeout: int = 300  # seconds


class AlertsConfig(BaseSettings):
    """Alert configuration"""
    enabled: bool = True
    new_device: bool = True
    new_port: bool = True
    threshold_ports: int = 10  # Alert if more than X new ports


class EmailConfig(BaseSettings):
    """Email notification configuration"""
    enabled: bool = False
    smtp_server: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""  # Loaded from ARGUS_EMAIL_SMTP_PASSWORD env var
    from_address: str = ""
    recipients: List[str] = []
    
    model_config = ConfigDict(
        env_prefix="ARGUS_EMAIL_",
        env_file=".env"
    )


class WebhookConfig(BaseSettings):
    """Webhook notification configuration"""
    enabled: bool = False
    url: str = ""
    secret: Optional[str] = None  # Loaded from ARGUS_WEBHOOK_SECRET env var
    
    model_config = ConfigDict(
        env_prefix="ARGUS_WEBHOOK_",
        env_file=".env"
    )


class NotificationsConfig(BaseSettings):
    """Notifications configuration"""
    email: EmailConfig = EmailConfig()
    webhook: WebhookConfig = WebhookConfig()


class DatabaseConfig(BaseSettings):
    """Database configuration"""
    type: str = "sqlite"
    path: str = "./data/argus.db"
    retention_days: int = 365


class WebConfig(BaseSettings):
    """Web server configuration"""
    host: str = "0.0.0.0"
    port: int = 8080
    enable_auth: bool = False
    username: Optional[str] = None
    password: Optional[str] = None


class ScheduleConfig(BaseSettings):
    """Schedule configuration - managed by scheduler module"""
    model_config = ConfigDict(extra="allow")
    jobs: List[Any] = []


class SecurityConfig(BaseSettings):
    """Security configuration"""
    secure_cookies: bool = False  # Set True for HTTPS deployments
    rate_limit_login: str = "5/minute"  # Login attempts rate limit


class CVEIntegrationConfig(BaseSettings):
    """CVE (Common Vulnerabilities and Exposures) integration configuration"""
    enabled: bool = False
    api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key: Optional[str] = None  # Loaded from ARGUS_CVE_API_KEY env var
    cache_hours: int = 24  # How long to cache CVE data
    
    model_config = ConfigDict(
        env_prefix="ARGUS_CVE_",
        env_file=".env"
    )


class UniFiIntegrationConfig(BaseSettings):
    """UniFi Network Controller integration configuration"""
    enabled: bool = False
    controller_url: str = ""  # e.g., https://192.168.1.1 or https://unifi.ui.com
    controller_type: str = "udm"  # self_hosted, udm, cloud
    username: Optional[str] = None
    password: Optional[str] = None  # Loaded from ARGUS_UNIFI_PASSWORD env var
    api_key: Optional[str] = None  # Loaded from ARGUS_UNIFI_API_KEY env var
    site_id: str = "default"
    verify_ssl: bool = False  # Self-signed certs are common
    cache_seconds: int = 60  # How long to cache client data
    sync_on_scan: bool = True  # Auto-enrich devices after scans
    include_offline_clients: bool = False  # Include disconnected clients
    
    model_config = ConfigDict(
        env_prefix="ARGUS_UNIFI_",
        env_file=".env"
    )


class PiHoleIntegrationConfig(BaseSettings):
    """Pi-hole DNS integration configuration"""
    enabled: bool = False
    pihole_url: str = ""  # e.g., http://pi.hole or http://192.168.1.2
    api_token: Optional[str] = None  # Loaded from ARGUS_PIHOLE_API_TOKEN env var
    verify_ssl: bool = False
    cache_seconds: int = 60  # How long to cache data
    sync_on_scan: bool = True  # Auto-enrich devices after scans
    
    model_config = ConfigDict(
        env_prefix="ARGUS_PIHOLE_",
        env_file=".env"
    )


class AdGuardIntegrationConfig(BaseSettings):
    """AdGuard Home DNS integration configuration"""
    enabled: bool = False
    adguard_url: str = ""  # e.g., http://192.168.1.2:3000
    username: Optional[str] = None
    password: Optional[str] = None  # Loaded from ARGUS_ADGUARD_PASSWORD env var
    verify_ssl: bool = False
    cache_seconds: int = 60  # How long to cache data
    sync_on_scan: bool = True  # Auto-enrich devices after scans
    
    model_config = ConfigDict(
        env_prefix="ARGUS_ADGUARD_",
        env_file=".env"
    )


class IntegrationsConfig(BaseSettings):
    """External integrations configuration"""
    cve: CVEIntegrationConfig = CVEIntegrationConfig()
    unifi: UniFiIntegrationConfig = UniFiIntegrationConfig()
    pihole: PiHoleIntegrationConfig = PiHoleIntegrationConfig()
    adguard: AdGuardIntegrationConfig = AdGuardIntegrationConfig()


class Config(BaseSettings):
    """Main application configuration"""
    network: NetworkConfig = NetworkConfig()
    scanning: ScanningConfig = ScanningConfig()
    alerts: AlertsConfig = AlertsConfig()
    notifications: NotificationsConfig = NotificationsConfig()
    database: DatabaseConfig = DatabaseConfig()
    web: WebConfig = WebConfig()
    schedule: ScheduleConfig = ScheduleConfig()
    security: SecurityConfig = SecurityConfig()
    integrations: IntegrationsConfig = IntegrationsConfig()

    class Config:
        env_file = ".env"
        env_nested_delimiter = "__"

    @classmethod
    def from_yaml(cls, yaml_path: str = "config.yaml") -> "Config":
        """Load configuration from YAML file"""
        if not os.path.exists(yaml_path):
            # Return default configuration
            return cls()

        with open(yaml_path, "r") as f:
            yaml_data = yaml.safe_load(f)

        if yaml_data is None:
            return cls()

        # Convert nested dict to Config object
        return cls(**yaml_data)


# Global config instance
config: Optional[Config] = None


def get_config() -> Config:
    """Get global configuration instance"""
    global config
    if config is None:
        # Try to load from YAML, fallback to env vars
        config = Config.from_yaml()
    return config


def reload_config():
    """Reload configuration from file"""
    global config
    config = Config.from_yaml()
    return config


def save_config(config_obj: Config, yaml_path: str = "config.yaml"):
    """
    Save configuration to YAML file.
    
    NOTE: Sensitive fields (passwords, API keys, tokens) are redacted in the YAML file.
    Set these via environment variables instead:
    - ARGUS_EMAIL_SMTP_PASSWORD
    - ARGUS_WEBHOOK_SECRET
    - ARGUS_CVE_API_KEY
    - ARGUS_UNIFI_PASSWORD
    - ARGUS_UNIFI_API_KEY
    - ARGUS_PIHOLE_API_TOKEN
    - ARGUS_ADGUARD_PASSWORD
    """
    # Convert Config object to dict
    config_dict = {
        "network": {
            "subnet": config_obj.network.subnet,
            "scan_schedule": config_obj.network.scan_schedule,
            "scan_profile": config_obj.network.scan_profile,
        },
        "scanning": {
            "port_range": config_obj.scanning.port_range,
            "enable_os_detection": config_obj.scanning.enable_os_detection,
            "enable_service_detection": config_obj.scanning.enable_service_detection,
            "timeout": config_obj.scanning.timeout,
        },
        "alerts": {
            "enabled": config_obj.alerts.enabled,
            "new_device": config_obj.alerts.new_device,
            "new_port": config_obj.alerts.new_port,
            "threshold_ports": config_obj.alerts.threshold_ports,
        },
        "notifications": {
            "email": {
                "enabled": config_obj.notifications.email.enabled,
                "smtp_server": config_obj.notifications.email.smtp_server,
                "smtp_port": config_obj.notifications.email.smtp_port,
                "smtp_username": config_obj.notifications.email.smtp_username,
                # SECURITY: Password redacted - set via ARGUS_EMAIL_SMTP_PASSWORD env var
                "smtp_password": "***REDACTED***" if config_obj.notifications.email.smtp_password else None,
                "from_address": config_obj.notifications.email.from_address,
                "recipients": config_obj.notifications.email.recipients,
            },
            "webhook": {
                "enabled": config_obj.notifications.webhook.enabled,
                "url": config_obj.notifications.webhook.url,
                # SECURITY: Secret redacted - set via ARGUS_WEBHOOK_SECRET env var
                "secret": "***REDACTED***" if config_obj.notifications.webhook.secret else None,
            },
        },
        "database": {
            "type": config_obj.database.type,
            "path": config_obj.database.path,
            "retention_days": config_obj.database.retention_days,
        },
        "web": {
            "host": config_obj.web.host,
            "port": config_obj.web.port,
            "enable_auth": config_obj.web.enable_auth,
            "username": config_obj.web.username,
            "password": config_obj.web.password,
        },
        "integrations": {
            "cve": {
                "enabled": config_obj.integrations.cve.enabled,
                "api_url": config_obj.integrations.cve.api_url,
                # SECURITY: API key redacted - set via ARGUS_CVE_API_KEY env var
                "api_key": "***REDACTED***" if config_obj.integrations.cve.api_key else None,
                "cache_hours": config_obj.integrations.cve.cache_hours,
            },
            "unifi": {
                "enabled": config_obj.integrations.unifi.enabled,
                "controller_url": config_obj.integrations.unifi.controller_url,
                "controller_type": config_obj.integrations.unifi.controller_type,
                "username": config_obj.integrations.unifi.username,
                # SECURITY: Password redacted - set via ARGUS_UNIFI_PASSWORD env var
                "password": "***REDACTED***" if config_obj.integrations.unifi.password else None,
                # SECURITY: API key redacted - set via ARGUS_UNIFI_API_KEY env var
                "api_key": "***REDACTED***" if config_obj.integrations.unifi.api_key else None,
                "site_id": config_obj.integrations.unifi.site_id,
                "verify_ssl": config_obj.integrations.unifi.verify_ssl,
                "cache_seconds": config_obj.integrations.unifi.cache_seconds,
                "sync_on_scan": config_obj.integrations.unifi.sync_on_scan,
                "include_offline_clients": config_obj.integrations.unifi.include_offline_clients,
            },
            "pihole": {
                "enabled": config_obj.integrations.pihole.enabled,
                "pihole_url": config_obj.integrations.pihole.pihole_url,
                # SECURITY: API token redacted - set via ARGUS_PIHOLE_API_TOKEN env var
                "api_token": "***REDACTED***" if config_obj.integrations.pihole.api_token else None,
                "verify_ssl": config_obj.integrations.pihole.verify_ssl,
                "cache_seconds": config_obj.integrations.pihole.cache_seconds,
                "sync_on_scan": config_obj.integrations.pihole.sync_on_scan,
            },
            "adguard": {
                "enabled": config_obj.integrations.adguard.enabled,
                "adguard_url": config_obj.integrations.adguard.adguard_url,
                "username": config_obj.integrations.adguard.username,
                # SECURITY: Password redacted - set via ARGUS_ADGUARD_PASSWORD env var
                "password": "***REDACTED***" if config_obj.integrations.adguard.password else None,
                "verify_ssl": config_obj.integrations.adguard.verify_ssl,
                "cache_seconds": config_obj.integrations.adguard.cache_seconds,
                "sync_on_scan": config_obj.integrations.adguard.sync_on_scan,
            },
        },
    }

    with open(yaml_path, "w") as f:
        yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)
