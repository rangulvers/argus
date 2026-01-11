"""AdGuard Home integration exceptions"""


class AdGuardError(Exception):
    """Base exception for AdGuard Home integration"""
    pass


class AdGuardConnectionError(AdGuardError):
    """Failed to connect to AdGuard Home"""
    pass


class AdGuardAuthenticationError(AdGuardError):
    """Authentication with AdGuard Home failed"""
    pass


class AdGuardAPIError(AdGuardError):
    """AdGuard Home API request failed"""
    pass
