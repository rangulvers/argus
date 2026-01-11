"""Pi-hole integration exceptions"""


class PiHoleError(Exception):
    """Base exception for Pi-hole integration"""
    pass


class PiHoleConnectionError(PiHoleError):
    """Failed to connect to Pi-hole"""
    pass


class PiHoleAuthenticationError(PiHoleError):
    """Authentication with Pi-hole failed"""
    pass


class PiHoleAPIError(PiHoleError):
    """Pi-hole API request failed"""
    pass
