"""Audit logging helpers for Argus"""

from datetime import datetime
from typing import Optional, Any, Dict
from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog


# Action constants
class AuditAction:
    # Authentication
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    SETUP_COMPLETE = "setup_complete"

    # API Keys
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_USED = "api_key_used"

    # Scanning
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"

    # Devices
    DEVICE_UPDATED = "device_updated"
    DEVICE_TRUSTED = "device_trusted"
    DEVICE_UNTRUSTED = "device_untrusted"

    # Configuration
    CONFIG_UPDATED = "config_updated"
    SCHEDULE_CREATED = "schedule_created"
    SCHEDULE_UPDATED = "schedule_updated"
    SCHEDULE_DELETED = "schedule_deleted"


# Resource type constants
class ResourceType:
    USER = "user"
    DEVICE = "device"
    SCAN = "scan"
    API_KEY = "api_key"
    CONFIG = "config"
    SCHEDULE = "schedule"


def get_client_ip(request: Request) -> Optional[str]:
    """Extract client IP from request, handling proxies."""
    # Check for forwarded header (behind proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()

    # Check for real IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fall back to direct client
    if request.client:
        return request.client.host

    return None


def get_user_agent(request: Request) -> Optional[str]:
    """Extract user agent from request."""
    ua = request.headers.get("User-Agent")
    if ua and len(ua) > 255:
        ua = ua[:255]
    return ua


def log_action(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    request: Optional[Request] = None,
    success: bool = True
) -> AuditLog:
    """
    Log an audit action.

    Args:
        db: Database session
        action: Action type (use AuditAction constants)
        user_id: ID of the user performing the action
        username: Username (denormalized for quick access)
        resource_type: Type of resource affected (use ResourceType constants)
        resource_id: ID of the affected resource
        details: Additional context as dict
        request: FastAPI request object for IP/user agent
        success: Whether the action succeeded

    Returns:
        The created AuditLog entry
    """
    ip_address = None
    user_agent = None

    if request:
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)

    audit_log = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success
    )

    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)

    return audit_log


def log_from_request(
    db: Session,
    request: Request,
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    success: bool = True
) -> AuditLog:
    """
    Log an audit action, extracting user info from request.

    Uses the current_user from request state if available.
    """
    from app.auth import get_current_user

    user_id = None
    username = None

    current_user = get_current_user(request)
    if current_user:
        user_id = current_user.get("user_id")
        username = current_user.get("username")

    return log_action(
        db=db,
        action=action,
        user_id=user_id,
        username=username,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        request=request,
        success=success
    )
