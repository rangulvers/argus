"""Argus FastAPI Application"""

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import desc
from typing import List, Optional
from datetime import datetime
from pathlib import Path
import logging
import io
import zipfile
import csv

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.database import get_db, init_db
from app.models import Scan, Device, Port, Change, DeviceHistory, User, APIKey, AuditLog
from app.audit import log_action, log_from_request, AuditAction, ResourceType
from app.scanner import NetworkScanner
from app.utils.change_detector import ChangeDetector
from app.config import get_config, save_config, reload_config
from app.scheduler import (
    init_scheduler, get_all_schedules, add_schedule_job,
    update_schedule_job, delete_schedule_job, run_retention_cleanup
)
from app.auth import (
    hash_password, verify_password, set_session_cookie,
    clear_session_cookie, get_current_user, requires_auth,
    generate_api_key, hash_api_key, verify_api_key,
    get_api_key_prefix, get_api_key_from_request
)
from app.version import get_version, get_build_info
from app.utils.device_icons import detect_device_type, get_device_icon_info
from app.update_checker import get_update_checker
from pydantic import BaseModel

# Import validation schemas
from app.schemas import (
    DeviceUpdate,
    ScanRequest,
    SingleDeviceScanRequest,
    NetworkConfigUpdate,
    ScanningConfigUpdate,
    ConfigUpdate,
    CVEIntegrationUpdate,
    UniFiIntegrationUpdate,
    PiHoleIntegrationUpdate,
    AdGuardIntegrationUpdate,
    APIKeyCreateRequest,
    ScheduleJobCreate,
    ScheduleJobUpdate,
    ScanResponse,
    PortResponse,
    APIKeyCreatedResponse
)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def error_response(status_code: int, message: str, detail: str = None) -> JSONResponse:
    """Return a structured JSON error response."""
    content = {"error": message}
    if detail:
        content["detail"] = detail
    return JSONResponse(status_code=status_code, content=content)


# Initialize FastAPI app
app = FastAPI(
    title="Argus",
    description="The All-Seeing Network Monitor",
    version=get_version()
)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Handle rate limit exceeded errors"""
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please try again later."}
    )


# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")

# Import shared templates instance
from app.templates_config import templates

# Initialize database and scheduler on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database and scheduler on startup"""
    init_db()
    logger.info("Database initialized")
    init_scheduler()
    logger.info("Scheduler initialized")


# Authentication middleware
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Check authentication for protected routes"""
    from fastapi.responses import JSONResponse
    path = request.url.path
    is_api_route = path.startswith("/api/")

    # Skip auth check for public paths
    if not requires_auth(path):
        return await call_next(request)

    # SECURITY FIX: Use context manager to prevent database session leaks
    # Session is created inside try block to ensure cleanup even on early exceptions
    from app.database import get_middleware_db

    try:
        with get_middleware_db() as db:
            # Check if any users exist
            user_count = db.query(User).count()

            if user_count == 0:
                # No users - redirect to setup (except for setup page itself)
                if path != "/setup":
                    if is_api_route:
                        return JSONResponse(
                            status_code=401,
                            content={"detail": "No users configured. Please complete setup."}
                        )
                    return RedirectResponse(url="/setup", status_code=302)
                return await call_next(request)

            # For API routes, also check for API key authentication
            if is_api_route:
                api_key = get_api_key_from_request(request)
                if api_key:
                    # SECURITY FIX: Optimize API key validation to prevent DoS and timing attacks
                    # Step 1: Extract prefix for fast lookup (no expensive hashing yet)
                    from app.auth import get_api_key_prefix, verify_api_key
                    key_prefix = get_api_key_prefix(api_key)

                    # Step 2: Query by indexed prefix only (fast database lookup)
                    api_key_candidates = db.query(APIKey).filter(
                        APIKey.key_prefix == key_prefix,
                        APIKey.is_revoked == False
                    ).all()

                    # Step 3: Verify hash only for matching prefix candidates (1-2 max)
                    valid_key = None
                    for candidate in api_key_candidates:
                        if verify_api_key(api_key, candidate.key_hash):
                            valid_key = candidate
                            break

                    # Step 4: Constant-time dummy verification to prevent timing attacks
                    # Always perform at least one hash operation to keep timing consistent
                    if not valid_key and not api_key_candidates:
                        # No candidates found - do dummy hash to prevent timing leak
                        from app.auth import hash_api_key
                        _ = hash_api_key("dummy_key_" + api_key[:8])

                    if valid_key:
                        # Check expiration
                        if valid_key.expires_at and valid_key.expires_at < datetime.utcnow():
                            return JSONResponse(
                                status_code=401,
                                content={"detail": "API key has expired"}
                            )

                        # Update last used timestamp
                        valid_key.last_used_at = datetime.utcnow()
                        db.commit()

                        # API key is valid - continue
                        return await call_next(request)

            # Check if user is authenticated via session
            current_user = get_current_user(request)
            if not current_user:
                # Not logged in
                if is_api_route:
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "Authentication required. Use session cookie or API key."}
                    )
                return RedirectResponse(url="/login", status_code=302)

            # User is authenticated - continue
            return await call_next(request)
    except Exception as e:
        # Log any unexpected errors during authentication
        logger.error(f"Error in auth_middleware: {e}", exc_info=True)
        if is_api_route:
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error during authentication"}
            )
        return RedirectResponse(url="/login", status_code=302)


# Security headers middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)

    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"

    # XSS protection (legacy, but still useful)
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Control referrer information
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Add HSTS header if secure cookies are enabled (indicates HTTPS deployment)
    config = get_config()
    if config.security.secure_cookies:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


# ============================================================================
# Response Schemas (not in schemas.py - used only internally)
# ============================================================================

class DeviceResponse(BaseModel):
    id: int
    ip_address: str
    mac_address: Optional[str]
    hostname: Optional[str]
    vendor: Optional[str]
    os_name: Optional[str]
    status: str
    port_count: int

    class Config:
        from_attributes = True


class ChangeResponse(BaseModel):
    id: int
    change_type: str
    severity: str
    device_ip: Optional[str]
    device_mac: Optional[str]
    port_number: Optional[int]
    protocol: Optional[str]
    description: str
    detected_at: datetime

    class Config:
        from_attributes = True


class APIKeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    created_at: datetime
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    is_revoked: bool

    class Config:
        from_attributes = True


class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    username: Optional[str]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    details: Optional[dict]
    ip_address: Optional[str]
    success: bool

    class Config:
        from_attributes = True


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow()}


# Version endpoint
@app.get("/api/version")
async def get_app_version():
    """Get application version and build information"""
    return get_build_info()


@app.get("/api/stats")
async def get_stats(db: Session = Depends(get_db)):
    """Get network statistics for dashboard widget integration.

    Returns key metrics suitable for homepage (gethomepage.dev) widgets:
    - total_devices: Total unique devices ever discovered (from DeviceHistory)
    - devices_at_risk: Devices with medium/high/critical risk level
    - critical: Number of critical risk devices
    - high: Number of high risk devices
    - last_scan: Timestamp of the most recent scan (ISO format)
    """
    # Get total unique devices from DeviceHistory (persists across all scans)
    total_devices = db.query(DeviceHistory).count()

    # Get the latest completed network scan (not single-device scans) - matches dashboard logic
    latest_scan = (
        db.query(Scan)
        .options(selectinload(Scan.devices))
        .filter(
            Scan.status == "completed",
            Scan.scan_type == "network"
        )
        .order_by(desc(Scan.started_at))
        .first()
    )

    # Calculate risk stats from the latest scan's devices
    devices_at_risk = 0
    critical_devices = 0
    high_risk_devices = 0

    if latest_scan:
        for device in latest_scan.devices:
            if device.risk_level in ("medium", "high", "critical"):
                devices_at_risk += 1
            if device.risk_level == "critical":
                critical_devices += 1
            elif device.risk_level == "high":
                high_risk_devices += 1

    return {
        "total_devices": total_devices,
        "devices_at_risk": devices_at_risk,
        "critical": critical_devices,
        "high": high_risk_devices,
        "last_scan": latest_scan.started_at.isoformat() if latest_scan and latest_scan.started_at else None
    }


@app.get("/api/trends")
async def get_trend_data(
    days: int = 30,
    db: Session = Depends(get_db)
):
    """Get historical trend data for charts.

    Returns aggregated data per scan for:
    - Device count over time
    - Risk score trends
    - Open port counts
    - Changes per scan
    """
    from datetime import timedelta
    from sqlalchemy import func

    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Get completed network scans within the time range
    scans = (
        db.query(Scan)
        .options(selectinload(Scan.devices).selectinload(Device.ports))
        .filter(
            Scan.status == "completed",
            Scan.scan_type == "network",
            Scan.started_at >= cutoff_date
        )
        .order_by(Scan.started_at)
        .all()
    )

    # Build trend data
    trend_data = {
        "labels": [],  # Timestamps for x-axis
        "device_counts": [],
        "risk_scores": [],  # Average risk score per scan
        "port_counts": [],
        "change_counts": [],
        "at_risk_counts": []  # Devices with medium/high/critical risk
    }

    for scan in scans:
        # Format timestamp for label
        trend_data["labels"].append(
            scan.started_at.strftime("%Y-%m-%d %H:%M")
        )
        trend_data["device_counts"].append(scan.devices_found)

        # Calculate risk metrics
        total_risk_score = 0
        at_risk = 0
        total_ports = 0

        for device in scan.devices:
            total_risk_score += device.risk_score or 0
            total_ports += len(device.ports)
            if device.risk_level in ("medium", "high", "critical"):
                at_risk += 1

        avg_risk = total_risk_score / scan.devices_found if scan.devices_found > 0 else 0
        trend_data["risk_scores"].append(round(avg_risk, 1))
        trend_data["port_counts"].append(total_ports)
        trend_data["at_risk_counts"].append(at_risk)

        # Count changes for this scan
        change_count = db.query(Change).filter(Change.scan_id == scan.id).count()
        trend_data["change_counts"].append(change_count)

    # Also get summary stats
    summary = {
        "total_scans": len(scans),
        "days": days,
        "avg_devices": round(sum(trend_data["device_counts"]) / len(scans), 1) if scans else 0,
        "avg_risk_score": round(sum(trend_data["risk_scores"]) / len(scans), 1) if scans else 0,
        "total_changes": sum(trend_data["change_counts"])
    }

    return {
        "trends": trend_data,
        "summary": summary
    }


@app.get("/api/dashboard/distributions")
async def get_dashboard_distributions(db: Session = Depends(get_db)):
    """Get distribution data for dashboard charts.

    Returns aggregated data for:
    - Risk level distribution (for doughnut chart)
    - Device type distribution (for doughnut chart)
    - Top ports frequency (for polar area chart)
    - Security posture metrics (for radar chart)
    """
    # Get the latest completed network scan
    latest_scan = db.query(Scan).filter(
        Scan.status == "completed",
        Scan.scan_type == "network"
    ).order_by(desc(Scan.started_at)).first()

    if not latest_scan:
        return {
            "risk_distribution": {},
            "device_types": {},
            "top_ports": [],
            "security_posture": {},
            "has_data": False
        }

    devices = (
        db.query(Device)
        .options(selectinload(Device.ports))
        .filter(Device.scan_id == latest_scan.id)
        .all()
    )

    # Risk distribution
    risk_distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "safe": 0
    }
    for device in devices:
        risk = device.risk_level or "none"
        if risk == "none":
            risk_distribution["safe"] += 1
        elif risk in risk_distribution:
            risk_distribution[risk] += 1

    # Device type distribution
    device_types = {}
    for device in devices:
        dtype = device.device_type or "Unknown"
        device_types[dtype] = device_types.get(dtype, 0) + 1

    # Sort by count and take top 8
    device_types = dict(sorted(device_types.items(), key=lambda x: x[1], reverse=True)[:8])

    # Top ports frequency
    port_counts = {}
    for device in devices:
        for port in device.ports:
            port_key = f"{port.port_number}"
            if port.service_name:
                port_key = f"{port.port_number} ({port.service_name})"
            port_counts[port_key] = port_counts.get(port_key, 0) + 1

    # Sort by count and take top 10
    top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Security posture metrics (normalized to 0-100 scale for radar chart)
    total_devices = len(devices)
    at_risk_devices = sum(1 for d in devices if d.risk_level in ("medium", "high", "critical"))
    trusted_devices = sum(1 for d in devices if d.is_trusted)
    devices_with_ports = sum(1 for d in devices if len(d.ports) > 0)

    # Calculate total open ports
    total_ports = sum(len(d.ports) for d in devices)

    # Get recent changes count
    from datetime import timedelta
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_changes = db.query(Change).filter(Change.detected_at >= week_ago).count()

    # Normalize metrics (higher is better for security)
    security_posture = {
        "device_security": round(100 - (at_risk_devices / total_devices * 100) if total_devices > 0 else 100, 1),
        "trust_coverage": round((trusted_devices / total_devices * 100) if total_devices > 0 else 0, 1),
        "port_exposure": round(100 - min(total_ports * 2, 100), 1),  # Lower ports = better
        "network_stability": round(100 - min(recent_changes * 5, 100), 1),  # Fewer changes = more stable
        "monitoring_coverage": round((devices_with_ports / total_devices * 100) if total_devices > 0 else 0, 1),
    }

    return {
        "risk_distribution": risk_distribution,
        "device_types": device_types,
        "top_ports": [{"port": p[0], "count": p[1]} for p in top_ports],
        "security_posture": security_posture,
        "has_data": True,
        "total_devices": total_devices,
        "scan_id": latest_scan.id
    }


@app.get("/api/updates/check")
async def check_for_updates(force: bool = False):
    """Check for available updates from GitHub releases.

    Args:
        force: Force refresh even if cached result exists
    """
    checker = get_update_checker()
    result = await checker.check_for_updates(force=force)
    return result


@app.get("/api/changes", response_model=List[ChangeResponse])
async def list_changes(
    scan_id: Optional[int] = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """List recent changes"""
    query = db.query(Change).order_by(desc(Change.detected_at))

    if scan_id:
        query = query.filter(Change.scan_id == scan_id)

    changes = query.limit(limit).all()

    return [
        ChangeResponse(
            id=change.id,
            change_type=change.change_type,
            severity=change.severity,
            device_ip=change.device_ip,
            device_mac=change.device_mac,
            port_number=change.port_number,
            protocol=change.protocol,
            description=change.description,
            detected_at=change.detected_at
        )
        for change in changes
    ]


@app.get("/api/scans/{current_id}/compare/{previous_id}")
async def compare_scans(
    current_id: int,
    previous_id: int,
    db: Session = Depends(get_db)
):
    """Compare two scans"""
    current_scan = (
        db.query(Scan)
        .options(selectinload(Scan.devices))
        .filter(Scan.id == current_id)
        .first()
    )
    previous_scan = (
        db.query(Scan)
        .options(selectinload(Scan.devices))
        .filter(Scan.id == previous_id)
        .first()
    )

    if not current_scan or not previous_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get changes for this comparison
    changes = (
        db.query(Change)
        .filter(Change.scan_id == current_id)
        .order_by(Change.detected_at)
        .all()
    )

    # Build comparison data
    current_devices = {d.mac_address or d.ip_address: d for d in current_scan.devices}
    previous_devices = {d.mac_address or d.ip_address: d for d in previous_scan.devices}

    added_devices = set(current_devices.keys()) - set(previous_devices.keys())
    removed_devices = set(previous_devices.keys()) - set(current_devices.keys())

    return {
        "current_scan": ScanResponse.model_validate(current_scan),
        "previous_scan": ScanResponse.model_validate(previous_scan),
        "changes": [ChangeResponse.model_validate(c) for c in changes],
        "summary": {
            "devices_added": len(added_devices),
            "devices_removed": len(removed_devices),
            "total_changes": len(changes)
        }
    }


# Register domain routers
from app.routers import auth, scans, devices, visualization, integrations, config, export, admin, pages

app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(devices.router)
app.include_router(visualization.router)
app.include_router(integrations.router)
app.include_router(config.router)
app.include_router(export.router)
app.include_router(admin.router)
app.include_router(pages.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
