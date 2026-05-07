"""Shared Jinja2 templates instance."""
from fastapi.templating import Jinja2Templates
from app.version import get_version
from app.utils.device_icons import detect_device_type, get_device_icon_info

templates = Jinja2Templates(directory="templates")
templates.env.globals["app_version"] = get_version()


def get_device_icon_type(device):
    """Template helper to get device icon type from a device object."""
    ports = [p.port_number for p in device.ports] if hasattr(device, 'ports') and device.ports else []
    return detect_device_type(
        vendor=device.vendor if hasattr(device, 'vendor') else None,
        hostname=device.hostname if hasattr(device, 'hostname') else None,
        os_name=device.os_name if hasattr(device, 'os_name') else None,
        device_type=device.device_type if hasattr(device, 'device_type') else None,
        ports=ports,
        mac_address=device.mac_address if hasattr(device, 'mac_address') else None,
        ip_address=device.ip_address if hasattr(device, 'ip_address') else None,
    )


templates.env.globals["get_device_icon_type"] = get_device_icon_type
templates.env.globals["get_device_icon_info"] = get_device_icon_info
