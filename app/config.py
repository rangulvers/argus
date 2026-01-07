"""Configuration management for Argus"""

from pydantic_settings import BaseSettings
from typing import Optional, List
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
    smtp_password: str = ""
    from_address: str = ""
    recipients: List[str] = []


class WebhookConfig(BaseSettings):
    """Webhook notification configuration"""
    enabled: bool = False
    url: str = ""
    secret: Optional[str] = None


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


class Config(BaseSettings):
    """Main application configuration"""
    network: NetworkConfig = NetworkConfig()
    scanning: ScanningConfig = ScanningConfig()
    alerts: AlertsConfig = AlertsConfig()
    notifications: NotificationsConfig = NotificationsConfig()
    database: DatabaseConfig = DatabaseConfig()
    web: WebConfig = WebConfig()

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
    """Save configuration to YAML file"""
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
                "smtp_password": config_obj.notifications.email.smtp_password,
                "from_address": config_obj.notifications.email.from_address,
                "recipients": config_obj.notifications.email.recipients,
            },
            "webhook": {
                "enabled": config_obj.notifications.webhook.enabled,
                "url": config_obj.notifications.webhook.url,
                "secret": config_obj.notifications.webhook.secret,
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
    }

    with open(yaml_path, "w") as f:
        yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)
