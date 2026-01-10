"""UniFi integration exceptions"""


class UniFiError(Exception):
    """Base exception for UniFi integration"""
    pass


class UniFiConnectionError(UniFiError):
    """Failed to connect to UniFi controller"""
    pass


class UniFiAuthenticationError(UniFiError):
    """Authentication with UniFi controller failed"""
    pass


class UniFiAPIError(UniFiError):
    """UniFi API request failed"""
    pass
