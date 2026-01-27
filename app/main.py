"""Argus FastAPI Application"""

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from datetime import datetime
import logging

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
    update_schedule_job, delete_schedule_job
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
templates = Jinja2Templates(directory="templates")

# Add version to template globals
templates.env.globals["app_version"] = get_version()


# Add device icon helper to templates
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

    # Get database session to check for users
    from app.database import SessionLocal
    db = SessionLocal()
    try:
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
    finally:
        db.close()


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
    latest_scan = db.query(Scan).filter(
        Scan.status == "completed",
        Scan.scan_type == "network"
    ).order_by(desc(Scan.started_at)).first()

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
    scans = db.query(Scan).filter(
        Scan.status == "completed",
        Scan.scan_type == "network",
        Scan.started_at >= cutoff_date
    ).order_by(Scan.started_at).all()

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

    devices = db.query(Device).filter(Device.scan_id == latest_scan.id).all()

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


# Authentication Endpoints
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, db: Session = Depends(get_db)):
    """Login page"""
    # If no users exist, redirect to setup
    user_count = db.query(User).count()
    if user_count == 0:
        return RedirectResponse(url="/setup", status_code=302)

    # If already logged in, redirect to dashboard
    current_user = get_current_user(request)
    if current_user:
        return RedirectResponse(url="/", status_code=302)

    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": None,
        "username": None
    })


@app.post("/login", response_class=HTMLResponse)
@limiter.limit("5/minute")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    remember: bool = Form(False),
    db: Session = Depends(get_db)
):
    """Process login form - rate limited to 5 attempts per minute"""
    # Find user
    user = db.query(User).filter(User.username == username).first()

    if not user or not verify_password(password, user.password_hash):
        # Log failed login attempt
        log_action(
            db=db,
            action=AuditAction.LOGIN_FAILED,
            username=username,
            resource_type=ResourceType.USER,
            details={"reason": "Invalid credentials"},
            request=request,
            success=False
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password",
            "username": username
        })

    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    # Log successful login
    log_action(
        db=db,
        action=AuditAction.LOGIN_SUCCESS,
        user_id=user.id,
        username=user.username,
        resource_type=ResourceType.USER,
        resource_id=user.id,
        request=request
    )

    # Create response with session cookie
    response = RedirectResponse(url="/", status_code=302)
    set_session_cookie(response, user.id, user.username, remember)
    return response


@app.get("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    """Logout and clear session"""
    # Log logout
    current_user = get_current_user(request)
    if current_user:
        log_action(
            db=db,
            action=AuditAction.LOGOUT,
            user_id=current_user.get("user_id"),
            username=current_user.get("username"),
            resource_type=ResourceType.USER,
            request=request
        )

    response = RedirectResponse(url="/login", status_code=302)
    clear_session_cookie(response)
    return response


@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request, db: Session = Depends(get_db)):
    """Initial setup page - create admin user"""
    # If users already exist, redirect to login
    user_count = db.query(User).count()
    if user_count > 0:
        return RedirectResponse(url="/login", status_code=302)

    return templates.TemplateResponse("setup.html", {
        "request": request,
        "error": None,
        "username": None
    })


@app.post("/setup", response_class=HTMLResponse)
async def setup_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Process setup form"""
    # If users already exist, redirect to login
    user_count = db.query(User).count()
    if user_count > 0:
        return RedirectResponse(url="/login", status_code=302)

    # Validate input
    if len(username) < 3:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "error": "Username must be at least 3 characters",
            "username": username
        })

    if len(password) < 8:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "error": "Password must be at least 8 characters",
            "username": username
        })

    if password != confirm_password:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "error": "Passwords do not match",
            "username": username
        })

    # Create user
    user = User(
        username=username,
        password_hash=hash_password(password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info(f"Created admin user: {username}")

    # Log setup completion
    log_action(
        db=db,
        action=AuditAction.SETUP_COMPLETE,
        user_id=user.id,
        username=user.username,
        resource_type=ResourceType.USER,
        resource_id=user.id,
        details={"first_user": True},
        request=request
    )

    # Create response with session cookie (auto-login)
    response = RedirectResponse(url="/", status_code=302)
    set_session_cookie(response, user.id, user.username, remember=True)
    return response


# API Endpoints
@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db)
):
    """Trigger a new network scan"""
    config = get_config()

    subnet = scan_request.subnet or config.network.subnet
    scan_profile = scan_request.scan_profile or config.network.scan_profile
    port_range = scan_request.port_range or config.scanning.port_range

    logger.info(f"Starting scan: {subnet}, profile: {scan_profile}")

    # Log scan started
    log_from_request(
        db=db,
        request=request,
        action=AuditAction.SCAN_STARTED,
        resource_type=ResourceType.SCAN,
        details={"subnet": subnet, "profile": scan_profile}
    )

    # Run scan in background
    def run_scan():
        scanner = NetworkScanner(db)
        scan = scanner.perform_scan(
            subnet=subnet,
            scan_profile=scan_profile,
            port_range=port_range,
            enable_os_detection=config.scanning.enable_os_detection,
            enable_service_detection=config.scanning.enable_service_detection,
        )

        # Detect changes if requested
        if scan_request.detect_changes and scan.status == "completed":
            detector = ChangeDetector(db)
            detector.detect_changes(scan.id)

    background_tasks.add_task(run_scan)

    # Return a placeholder response
    return ScanResponse(
        id=0,
        started_at=datetime.utcnow(),
        completed_at=None,
        status="queued",
        subnet=subnet,
        devices_found=0,
        scan_profile=scan_profile
    )


@app.get("/api/scans", response_model=List[ScanResponse])
async def list_scans(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """List recent scans"""
    scans = db.query(Scan).order_by(desc(Scan.started_at)).limit(limit).all()

    return [
        ScanResponse(
            id=scan.id,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            status=scan.status,
            subnet=scan.subnet,
            devices_found=scan.devices_found,
            scan_profile=scan.scan_profile
        )
        for scan in scans
    ]


@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get scan details"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse(
        id=scan.id,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        status=scan.status,
        subnet=scan.subnet,
        devices_found=scan.devices_found,
        scan_profile=scan.scan_profile
    )


@app.get("/api/scans/{scan_id}/devices", response_model=List[DeviceResponse])
async def list_scan_devices(scan_id: int, db: Session = Depends(get_db)):
    """List devices from a specific scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return [
        DeviceResponse(
            id=device.id,
            ip_address=device.ip_address,
            mac_address=device.mac_address,
            hostname=device.hostname,
            vendor=device.vendor,
            os_name=device.os_name,
            status=device.status,
            port_count=len(device.ports)
        )
        for device in scan.devices
    ]


@app.get("/api/devices/{device_id}/ports", response_model=List[PortResponse])
async def list_device_ports(device_id: int, db: Session = Depends(get_db)):
    """List ports for a specific device"""
    device = db.query(Device).filter(Device.id == device_id).first()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    return [
        PortResponse(
            port_number=port.port_number,
            protocol=port.protocol,
            state=port.state,
            service_name=port.service_name,
            service_version=port.service_version
        )
        for port in device.ports
    ]


@app.put("/api/devices/{device_id}")
async def update_device(
    device_id: int,
    update: DeviceUpdate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Update device properties (label, notes, is_trusted, zone)"""
    device = db.query(Device).filter(Device.id == device_id).first()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Track changes for audit log
    changes = {}
    if update.label is not None and device.label != update.label:
        changes["label"] = {"old": device.label, "new": update.label}
    if update.is_trusted is not None and device.is_trusted != update.is_trusted:
        changes["is_trusted"] = {"old": device.is_trusted, "new": update.is_trusted}
    if update.zone is not None and device.zone != update.zone:
        changes["zone"] = {"old": device.zone, "new": update.zone}

    # Update device fields
    if update.label is not None:
        device.label = update.label if update.label else None
    if update.notes is not None:
        device.notes = update.notes if update.notes else None
    if update.is_trusted is not None:
        device.is_trusted = update.is_trusted
    if update.zone is not None:
        device.zone = update.zone if update.zone else None

    # Also update DeviceHistory if MAC address exists
    if device.mac_address:
        history = db.query(DeviceHistory).filter(
            DeviceHistory.mac_address == device.mac_address
        ).first()
        if history:
            if update.label is not None:
                history.label = device.label
            if update.notes is not None:
                history.notes = device.notes
            if update.is_trusted is not None:
                history.is_trusted = device.is_trusted
            if update.zone is not None:
                history.zone = device.zone

    db.commit()
    db.refresh(device)

    # Log device update
    log_from_request(
        db=db,
        request=request,
        action=AuditAction.DEVICE_UPDATED,
        resource_type=ResourceType.DEVICE,
        resource_id=device_id,
        details={
            "ip_address": device.ip_address,
            "mac_address": device.mac_address,
            "changes": changes
        }
    )

    return {
        "id": device.id,
        "ip_address": device.ip_address,
        "mac_address": device.mac_address,
        "label": device.label,
        "notes": device.notes,
        "is_trusted": device.is_trusted,
        "zone": device.zone
    }


@app.get("/api/zones")
async def list_zones(db: Session = Depends(get_db)):
    """List all unique zones used across devices"""
    # Get unique zones from DeviceHistory (persistent) and current devices
    history_zones = db.query(DeviceHistory.zone).filter(
        DeviceHistory.zone.isnot(None),
        DeviceHistory.zone != ""
    ).distinct().all()

    device_zones = db.query(Device.zone).filter(
        Device.zone.isnot(None),
        Device.zone != ""
    ).distinct().all()

    # Combine and deduplicate
    all_zones = set()
    for (zone,) in history_zones:
        all_zones.add(zone)
    for (zone,) in device_zones:
        all_zones.add(zone)

    return {"zones": sorted(list(all_zones))}


# ==================== Visualization API Endpoints ====================

@app.get("/api/visualization/topology")
async def get_topology_data(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Get network topology data for visualization"""
    # Get the scan to use
    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
    else:
        scan = db.query(Scan).filter(Scan.status == "completed").order_by(desc(Scan.completed_at)).first()

    if not scan:
        return {"nodes": [], "edges": [], "groups": {}}

    devices = db.query(Device).filter(Device.scan_id == scan.id).all()

    # Build nodes and group by zone/subnet
    nodes = []
    groups = {}

    for device in devices:
        zone = device.zone or "Unknown"
        if zone not in groups:
            groups[zone] = {"color": _get_zone_color(zone), "count": 0}
        groups[zone]["count"] += 1

        # Determine node color based on risk
        node_color = _get_risk_color(device.risk_level)

        nodes.append({
            "id": device.id,
            "label": device.label or device.hostname or device.ip_address,
            "ip": device.ip_address,
            "mac": device.mac_address,
            "vendor": device.vendor,
            "hostname": device.hostname,
            "zone": zone,
            "risk_level": device.risk_level or "none",
            "risk_score": device.risk_score or 0,
            "ports_count": len(device.ports),
            "is_trusted": device.is_trusted,
            "color": node_color,
            "size": 20 + (device.risk_score or 0) * 2,  # Larger nodes = higher risk
        })

    # Create edges based on same subnet (simplified - all devices in same scan are connected to a central router node)
    edges = []
    # Add router/gateway as central node
    if nodes:
        # Detect gateway (usually .1 or .254)
        gateway_node = next(
            (n for n in nodes if n["ip"].endswith(".1") or n["ip"].endswith(".254")),
            None
        )
        gateway_id = gateway_node["id"] if gateway_node else "gateway"

        if not gateway_node:
            nodes.insert(0, {
                "id": "gateway",
                "label": "Gateway",
                "ip": scan.subnet.replace("/24", ".1") if scan.subnet else "Gateway",
                "zone": "Infrastructure",
                "risk_level": "none",
                "color": "#6b7280",
                "size": 30,
                "is_gateway": True
            })

        # Connect all devices to gateway
        for node in nodes:
            if node["id"] != gateway_id:
                edges.append({
                    "from": gateway_id,
                    "to": node["id"],
                    "color": "#4b5563"
                })

    return {
        "nodes": nodes,
        "edges": edges,
        "groups": groups,
        "scan_id": scan.id,
        "scan_date": scan.completed_at.isoformat() if scan.completed_at else None
    }


@app.get("/api/visualization/heatmap")
async def get_heatmap_data(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Get risk heatmap data for visualization"""
    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
    else:
        scan = db.query(Scan).filter(Scan.status == "completed").order_by(desc(Scan.completed_at)).first()

    if not scan:
        return {"devices": [], "summary": {}}

    devices = db.query(Device).filter(Device.scan_id == scan.id).all()

    # Group by risk level
    risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}

    heatmap_data = []
    for device in devices:
        risk = device.risk_level or "none"
        risk_summary[risk] = risk_summary.get(risk, 0) + 1

        # Get device icon type
        ports = [p.port_number for p in device.ports] if device.ports else []
        icon_type = detect_device_type(
            vendor=device.vendor,
            hostname=device.hostname,
            os_name=device.os_name,
            device_type=device.device_type,
            ports=ports,
            mac_address=device.mac_address,
            ip_address=device.ip_address,
        )
        icon_info = get_device_icon_info(icon_type)

        heatmap_data.append({
            "id": device.id,
            "ip": device.ip_address,
            "label": device.label or device.hostname or device.ip_address,
            "zone": device.zone or "Unknown",
            "risk_level": risk,
            "risk_score": device.risk_score or 0,
            "ports_count": len(device.ports),
            "is_trusted": device.is_trusted,
            "threat_summary": device.threat_summary,
            "icon_type": icon_type,
            "device_type_label": icon_info["label"],
        })

    # Sort by risk score descending
    heatmap_data.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "devices": heatmap_data,
        "summary": risk_summary,
        "scan_id": scan.id
    }


@app.get("/api/visualization/port-matrix")
async def get_port_matrix_data(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Get port/service matrix data for visualization"""
    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
    else:
        scan = db.query(Scan).filter(Scan.status == "completed").order_by(desc(Scan.completed_at)).first()

    if not scan:
        return {"devices": [], "ports": [], "matrix": []}

    devices = db.query(Device).filter(Device.scan_id == scan.id).all()

    # Collect all unique ports
    all_ports = set()
    device_ports = {}

    for device in devices:
        device_ports[device.id] = {
            "id": device.id,
            "ip": device.ip_address,
            "label": device.label or device.hostname or device.ip_address,
            "ports": {}
        }
        for port in device.ports:
            all_ports.add(port.port_number)
            device_ports[device.id]["ports"][port.port_number] = {
                "service": port.service_name,
                "state": port.state,
                "product": port.service_product
            }

    # Sort ports
    sorted_ports = sorted(list(all_ports))

    # Build matrix
    matrix = []
    for device_id, device_data in device_ports.items():
        row = {
            "device_id": device_data["id"],
            "device_ip": device_data["ip"],
            "device_label": device_data["label"],
            "ports": []
        }
        for port in sorted_ports:
            if port in device_data["ports"]:
                row["ports"].append({
                    "port": port,
                    "open": True,
                    "service": device_data["ports"][port]["service"],
                    "product": device_data["ports"][port]["product"]
                })
            else:
                row["ports"].append({"port": port, "open": False})
        matrix.append(row)

    return {
        "ports": sorted_ports,
        "matrix": matrix,
        "scan_id": scan.id
    }


@app.get("/api/visualization/timeline")
async def get_timeline_data(
    device_id: Optional[int] = None,
    days: int = 30,
    db: Session = Depends(get_db)
):
    """Get device timeline data for visualization"""
    from datetime import timedelta

    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Get changes within the time range
    query = db.query(Change).filter(Change.detected_at >= cutoff_date)

    if device_id:
        device = db.query(Device).filter(Device.id == device_id).first()
        if device:
            query = query.filter(
                (Change.device_ip == device.ip_address) |
                (Change.device_mac == device.mac_address)
            )

    changes = query.order_by(Change.detected_at).all()

    timeline_events = []
    for change in changes:
        timeline_events.append({
            "id": change.id,
            "type": change.change_type,
            "severity": change.severity,
            "device_ip": change.device_ip,
            "device_mac": change.device_mac,
            "port": change.port_number,
            "description": change.description,
            "timestamp": change.detected_at.isoformat(),
            "scan_id": change.scan_id
        })

    # Also get scan history for context
    scans = db.query(Scan).filter(
        Scan.started_at >= cutoff_date,
        Scan.status == "completed"
    ).order_by(Scan.started_at).all()

    scan_events = [
        {
            "id": f"scan-{scan.id}",
            "type": "scan",
            "timestamp": scan.completed_at.isoformat() if scan.completed_at else scan.started_at.isoformat(),
            "devices_found": scan.devices_found,
            "profile": scan.scan_profile
        }
        for scan in scans
    ]

    return {
        "changes": timeline_events,
        "scans": scan_events,
        "days": days
    }


@app.get("/api/visualization/network-insights")
async def get_network_insights(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Get comprehensive network insights for enhanced visualizations.

    Returns data for:
    - Enhanced topology with UniFi connection data
    - Vendor distribution
    - Connection types (wired/wireless)
    - Traffic analysis
    - DNS query analysis (Pi-hole/AdGuard)
    - Signal strength for wireless devices
    """
    # Get the scan to use
    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
    else:
        scan = db.query(Scan).filter(
            Scan.status == "completed",
            Scan.scan_type == "network"
        ).order_by(desc(Scan.started_at)).first()

    if not scan:
        return {
            "has_data": False,
            "vendor_distribution": {},
            "connection_types": {},
            "traffic_data": [],
            "dns_analysis": {},
            "signal_strength": [],
            "topology_enhanced": {"nodes": [], "edges": [], "switches": [], "access_points": []}
        }

    devices = db.query(Device).filter(Device.scan_id == scan.id).all()

    # ===== Vendor Distribution =====
    vendor_counts = {}
    for device in devices:
        vendor = device.vendor or "Unknown"
        # Simplify vendor names (take first word/company name)
        if vendor != "Unknown":
            vendor = vendor.split()[0] if " " in vendor else vendor
            vendor = vendor.replace(",", "").replace("Inc.", "").replace("Ltd.", "")
        vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

    # Sort by count and take top 10
    vendor_distribution = dict(sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10])

    # ===== Connection Types & Traffic & Signal Strength =====
    connection_types = {"wired": 0, "wireless": 0, "unknown": 0}
    traffic_data = []
    signal_strength_data = []
    switches = {}  # switch_mac -> {name, port_count, devices: []}
    access_points = {}  # ssid -> {devices: [], channel, etc.}

    for device in devices:
        integrations = {}
        if device.threat_details and isinstance(device.threat_details, dict):
            integrations = device.threat_details.get("integrations", {})

        unifi_data = integrations.get("unifi", {})

        # Connection type
        conn_type = unifi_data.get("connection_type", "unknown")
        if conn_type in connection_types:
            connection_types[conn_type] += 1
        else:
            connection_types["unknown"] += 1

        # Traffic data (only for devices with UniFi data)
        if unifi_data and unifi_data.get("traffic"):
            traffic = unifi_data["traffic"]
            traffic_data.append({
                "device_id": device.id,
                "label": device.label or device.hostname or device.ip_address,
                "ip": device.ip_address,
                "tx_bytes": traffic.get("tx_bytes", 0),
                "rx_bytes": traffic.get("rx_bytes", 0),
                "total_bytes": traffic.get("tx_bytes", 0) + traffic.get("rx_bytes", 0),
                "is_online": unifi_data.get("is_online", True)
            })

        # Wireless signal strength
        if unifi_data.get("wireless"):
            wireless = unifi_data["wireless"]
            signal_strength_data.append({
                "device_id": device.id,
                "label": device.label or device.hostname or device.ip_address,
                "ip": device.ip_address,
                "signal": wireless.get("signal_strength", 0),
                "ssid": wireless.get("ssid", "Unknown"),
                "channel": wireless.get("channel"),
                "radio": wireless.get("radio", ""),
                "tx_rate": wireless.get("tx_rate", 0),
                "rx_rate": wireless.get("rx_rate", 0)
            })

            # Group by access point (SSID)
            ssid = wireless.get("ssid", "Unknown")
            if ssid not in access_points:
                access_points[ssid] = {
                    "ssid": ssid,
                    "channel": wireless.get("channel"),
                    "radio": wireless.get("radio"),
                    "devices": []
                }
            access_points[ssid]["devices"].append({
                "id": device.id,
                "label": device.label or device.hostname or device.ip_address,
                "signal": wireless.get("signal_strength", 0)
            })

        # Wired connections - group by switch
        if unifi_data.get("wired"):
            wired = unifi_data["wired"]
            switch_mac = wired.get("switch_mac", "unknown")
            if switch_mac not in switches:
                switches[switch_mac] = {
                    "mac": switch_mac,
                    "devices": []
                }
            switches[switch_mac]["devices"].append({
                "id": device.id,
                "label": device.label or device.hostname or device.ip_address,
                "port": wired.get("switch_port")
            })

    # Sort traffic data by total bytes (top consumers)
    traffic_data.sort(key=lambda x: x["total_bytes"], reverse=True)
    traffic_data = traffic_data[:15]  # Top 15

    # Sort signal strength by signal (weakest first for troubleshooting)
    signal_strength_data.sort(key=lambda x: x["signal"])

    # ===== DNS Analysis =====
    dns_analysis = {
        "total_queries": 0,
        "total_blocked": 0,
        "devices_with_dns": 0,
        "top_domains": {},
        "top_blocked": {},
        "query_types": {},
        "risk_scores": []
    }

    for device in devices:
        integrations = {}
        if device.threat_details and isinstance(device.threat_details, dict):
            integrations = device.threat_details.get("integrations", {})

        # Check Pi-hole or AdGuard
        dns_data = integrations.get("pihole") or integrations.get("adguard")
        if dns_data:
            dns_analysis["devices_with_dns"] += 1
            dns_analysis["total_queries"] += dns_data.get("queries_24h", 0)
            dns_analysis["total_blocked"] += dns_data.get("blocked_24h", 0)

            # Aggregate top domains
            for domain_info in dns_data.get("top_domains", []):
                domain = domain_info.get("domain", "")
                count = domain_info.get("count", 0)
                dns_analysis["top_domains"][domain] = dns_analysis["top_domains"].get(domain, 0) + count

            # Aggregate blocked domains
            for domain_info in dns_data.get("blocked_domains", []):
                domain = domain_info.get("domain", "")
                count = domain_info.get("count", 0)
                dns_analysis["top_blocked"][domain] = dns_analysis["top_blocked"].get(domain, 0) + count

            # Query types
            for qtype, count in dns_data.get("query_types", {}).items():
                dns_analysis["query_types"][qtype] = dns_analysis["query_types"].get(qtype, 0) + count

            # Risk scores
            if dns_data.get("dns_risk_score") is not None:
                dns_analysis["risk_scores"].append({
                    "device_id": device.id,
                    "label": device.label or device.hostname or device.ip_address,
                    "score": dns_data.get("dns_risk_score", 0)
                })

    # Sort and limit
    dns_analysis["top_domains"] = dict(sorted(
        dns_analysis["top_domains"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10])
    dns_analysis["top_blocked"] = dict(sorted(
        dns_analysis["top_blocked"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10])
    dns_analysis["risk_scores"].sort(key=lambda x: x["score"], reverse=True)
    dns_analysis["risk_scores"] = dns_analysis["risk_scores"][:10]

    # ===== Enhanced Topology =====
    # Build topology with actual connection data from UniFi
    topology_nodes = []
    topology_edges = []

    # Find gateway
    gateway = None
    for device in devices:
        if device.ip_address and (device.ip_address.endswith(".1") or device.ip_address.endswith(".254")):
            gateway = device
            break

    gateway_id = gateway.id if gateway else "gateway"

    # Add gateway node
    if not gateway:
        topology_nodes.append({
            "id": "gateway",
            "label": "Gateway",
            "type": "gateway",
            "group": "infrastructure"
        })

    # Add switch nodes
    for idx, (switch_mac, switch_info) in enumerate(switches.items()):
        switch_id = f"switch-{idx}"
        topology_nodes.append({
            "id": switch_id,
            "label": f"Switch",
            "type": "switch",
            "mac": switch_mac,
            "group": "infrastructure",
            "device_count": len(switch_info["devices"])
        })
        # Connect switch to gateway
        topology_edges.append({
            "from": gateway_id,
            "to": switch_id,
            "type": "wired"
        })
        # Connect devices to switch
        for dev in switch_info["devices"]:
            topology_edges.append({
                "from": switch_id,
                "to": dev["id"],
                "type": "wired",
                "port": dev.get("port")
            })

    # Add AP nodes
    for idx, (ssid, ap_info) in enumerate(access_points.items()):
        ap_id = f"ap-{idx}"
        topology_nodes.append({
            "id": ap_id,
            "label": ssid,
            "type": "access_point",
            "group": "infrastructure",
            "channel": ap_info.get("channel"),
            "device_count": len(ap_info["devices"])
        })
        # Connect AP to gateway
        topology_edges.append({
            "from": gateway_id,
            "to": ap_id,
            "type": "wired"
        })
        # Connect wireless devices to AP
        for dev in ap_info["devices"]:
            topology_edges.append({
                "from": ap_id,
                "to": dev["id"],
                "type": "wireless",
                "signal": dev.get("signal")
            })

    # Add all device nodes
    for device in devices:
        integrations = {}
        if device.threat_details and isinstance(device.threat_details, dict):
            integrations = device.threat_details.get("integrations", {})

        unifi_data = integrations.get("unifi", {})

        node = {
            "id": device.id,
            "label": device.label or device.hostname or device.ip_address,
            "ip": device.ip_address,
            "mac": device.mac_address,
            "type": device.device_type or "unknown",
            "risk_level": device.risk_level or "none",
            "risk_score": device.risk_score or 0,
            "is_trusted": device.is_trusted,
            "is_online": unifi_data.get("is_online", True),
            "connection_type": unifi_data.get("connection_type", "unknown"),
            "group": device.zone or "default"
        }
        topology_nodes.append(node)

        # If device has no switch/AP connection, connect directly to gateway
        has_connection = any(e["to"] == device.id for e in topology_edges)
        if not has_connection and device.id != gateway_id:
            topology_edges.append({
                "from": gateway_id,
                "to": device.id,
                "type": "unknown"
            })

    return {
        "has_data": True,
        "scan_id": scan.id,
        "total_devices": len(devices),
        "vendor_distribution": vendor_distribution,
        "connection_types": connection_types,
        "traffic_data": traffic_data,
        "dns_analysis": dns_analysis,
        "signal_strength": signal_strength_data,
        "topology_enhanced": {
            "nodes": topology_nodes,
            "edges": topology_edges,
            "switches": list(switches.values()),
            "access_points": list(access_points.values())
        }
    }


def _get_risk_color(risk_level: str) -> str:
    """Get color for risk level"""
    return {
        "critical": "#dc2626",  # red-600
        "high": "#ea580c",      # orange-600
        "medium": "#ca8a04",    # yellow-600
        "low": "#16a34a",       # green-600
        "none": "#6b7280",      # gray-500
    }.get(risk_level or "none", "#6b7280")


def _get_zone_color(zone: str) -> str:
    """Get color for zone"""
    colors = ["#3b82f6", "#8b5cf6", "#ec4899", "#14b8a6", "#f97316", "#84cc16"]
    return colors[hash(zone) % len(colors)]


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
    current_scan = db.query(Scan).filter(Scan.id == current_id).first()
    previous_scan = db.query(Scan).filter(Scan.id == previous_id).first()

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


@app.get("/api/device-history")
async def get_device_history(db: Session = Depends(get_db)):
    """Get device history for persistent tracking"""
    history = db.query(DeviceHistory).order_by(desc(DeviceHistory.last_seen)).all()

    return [
        {
            "mac_address": h.mac_address,
            "last_ip": h.last_ip,
            "last_hostname": h.last_hostname,
            "first_seen": h.first_seen,
            "last_seen": h.last_seen,
            "times_seen": h.times_seen,
            "label": h.label,
            "is_trusted": h.is_trusted
        }
        for h in history
    ]


# Web UI Endpoints
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    """Dashboard home page"""
    # Get latest network scan (not single-device scans)
    latest_scan = db.query(Scan).filter(
        Scan.status == "completed",
        Scan.scan_type == "network"
    ).order_by(desc(Scan.started_at)).first()

    # Get devices from latest scan
    devices = []
    if latest_scan:
        devices = latest_scan.devices

    # Get recent changes
    recent_changes = db.query(Change).order_by(desc(Change.detected_at)).limit(10).all()

    # Calculate stats
    total_scans = db.query(Scan).count()
    total_devices = len(devices) if latest_scan else 0
    total_ports = sum(len(d.ports) for d in devices) if devices else 0

    # Calculate threat stats
    devices_at_risk = 0
    critical_devices = 0
    high_risk_devices = 0
    if devices:
        for d in devices:
            if d.risk_level in ("medium", "high", "critical"):
                devices_at_risk += 1
            if d.risk_level == "critical":
                critical_devices += 1
            elif d.risk_level == "high":
                high_risk_devices += 1

    stats = {
        "total_scans": total_scans,
        "total_devices": total_devices,
        "total_ports": total_ports,
        "recent_changes": len(recent_changes),
        "devices_at_risk": devices_at_risk,
        "critical_devices": critical_devices,
        "high_risk_devices": high_risk_devices
    }

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "active_page": "dashboard",
        "stats": stats,
        "latest_scan": latest_scan,
        "devices": devices,
        "recent_changes": recent_changes,
        "current_user": get_current_user(request)
    })


@app.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request, scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Devices list page"""
    # Only show network scans in dropdown (not single-device scans)
    scans = db.query(Scan).filter(
        Scan.status == "completed",
        Scan.scan_type == "network"
    ).order_by(desc(Scan.started_at)).limit(20).all()

    # Get selected scan or latest network scan
    if scan_id:
        current_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    else:
        current_scan = scans[0] if scans else None

    devices = current_scan.devices if current_scan else []
    selected_scan_id = current_scan.id if current_scan else None

    return templates.TemplateResponse("devices.html", {
        "request": request,
        "active_page": "devices",
        "scans": scans,
        "current_scan": current_scan,
        "devices": devices,
        "selected_scan_id": selected_scan_id,
        "current_user": get_current_user(request)
    })


@app.get("/devices/{device_id}", response_class=HTMLResponse)
async def device_detail_page(request: Request, device_id: int, db: Session = Depends(get_db)):
    """Device detail page"""
    device = db.query(Device).filter(Device.id == device_id).first()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    return templates.TemplateResponse("device_detail.html", {
        "request": request,
        "active_page": "devices",
        "device": device,
        "current_user": get_current_user(request)
    })


@app.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request, db: Session = Depends(get_db)):
    """Scan history page"""
    scans = db.query(Scan).order_by(desc(Scan.started_at)).limit(50).all()

    return templates.TemplateResponse("scans.html", {
        "request": request,
        "active_page": "scans",
        "scans": scans,
        "current_user": get_current_user(request)
    })


@app.get("/visualization", response_class=HTMLResponse)
async def visualization_page(request: Request, db: Session = Depends(get_db)):
    """Network visualization page"""
    scans = db.query(Scan).filter(Scan.status == "completed").order_by(desc(Scan.completed_at)).limit(20).all()

    return templates.TemplateResponse("visualization.html", {
        "request": request,
        "active_page": "visualization",
        "scans": scans,
        "current_user": get_current_user(request)
    })


@app.get("/changes", response_class=HTMLResponse)
async def changes_page(request: Request, scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Changes/alerts page"""
    scans = db.query(Scan).filter(Scan.status == "completed").order_by(desc(Scan.started_at)).limit(20).all()

    query = db.query(Change).order_by(desc(Change.detected_at))
    if scan_id:
        query = query.filter(Change.scan_id == scan_id)

    changes = query.limit(100).all()

    return templates.TemplateResponse("changes.html", {
        "request": request,
        "active_page": "changes",
        "scans": scans,
        "changes": changes,
        "selected_scan_id": scan_id,
        "current_user": get_current_user(request)
    })


@app.get("/compare", response_class=HTMLResponse)
async def compare_page(
    request: Request,
    scan1: Optional[int] = None,
    scan2: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Scan comparison page"""
    scans = db.query(Scan).filter(Scan.status == "completed").order_by(desc(Scan.started_at)).limit(20).all()

    comparison = None
    if scan1 and scan2:
        scan1_obj = db.query(Scan).filter(Scan.id == scan1).first()
        scan2_obj = db.query(Scan).filter(Scan.id == scan2).first()

        if scan1_obj and scan2_obj:
            # Get devices
            scan1_devices = scan1_obj.devices
            scan2_devices = scan2_obj.devices

            # Build IP sets
            scan1_ips = {d.ip_address for d in scan1_devices}
            scan2_ips = {d.ip_address for d in scan2_devices}

            added_ips = scan2_ips - scan1_ips
            removed_ips = scan1_ips - scan2_ips

            # Get changes for scan2
            changes = db.query(Change).filter(Change.scan_id == scan2).order_by(Change.detected_at).all()

            # Separate change types
            devices_added = [c for c in changes if c.change_type == "device_added"]
            devices_removed = [c for c in changes if c.change_type == "device_removed"]
            ports_opened = [c for c in changes if c.change_type == "port_opened"]
            ports_closed = [c for c in changes if c.change_type == "port_closed"]

            comparison = {
                "scan1": scan1_obj,
                "scan2": scan2_obj,
                "scan1_devices": scan1_devices,
                "scan2_devices": scan2_devices,
                "added_ips": added_ips,
                "removed_ips": removed_ips,
                "changes": changes,
                "devices_added": devices_added,
                "devices_removed": devices_removed,
                "ports_opened": ports_opened,
                "ports_closed": ports_closed
            }

    return templates.TemplateResponse("compare.html", {
        "request": request,
        "active_page": "compare",
        "scans": scans,
        "scan1_id": scan1,
        "scan2_id": scan2,
        "comparison": comparison,
        "current_user": get_current_user(request)
    })


@app.get("/api/scan/status")
async def get_scan_status(db: Session = Depends(get_db)):
    """Check if there are any running scans"""
    running_scan = db.query(Scan).filter(Scan.status == "running").first()

    if running_scan:
        return {
            "scanning": True,
            "scan_id": running_scan.id,
            "scan_type": running_scan.scan_type,
            "subnet": running_scan.subnet,
            "profile": running_scan.scan_profile,
            "started_at": running_scan.started_at.isoformat()
        }
    return {"scanning": False}


@app.post("/api/scan/trigger")
async def trigger_scan_htmx(
    background_tasks: BackgroundTasks,
    profile: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Trigger network scan with optional profile selection"""
    config = get_config()
    scan_profile = profile if profile in ["quick", "normal", "intensive"] else config.network.scan_profile

    def run_scan():
        from app.database import SessionLocal
        db_session = SessionLocal()
        try:
            scanner = NetworkScanner(db_session)
            scan = scanner.perform_scan(
                subnet=config.network.subnet,
                scan_profile=scan_profile,
                port_range=config.scanning.port_range,
                enable_os_detection=config.scanning.enable_os_detection,
                enable_service_detection=config.scanning.enable_service_detection,
            )
            if scan.status == "completed":
                detector = ChangeDetector(db_session)
                detector.detect_changes(scan.id)
        finally:
            db_session.close()

    background_tasks.add_task(run_scan)
    return {"status": "started", "profile": scan_profile}


@app.post("/api/scan/device/{ip_address}")
async def trigger_device_scan(
    ip_address: str,
    background_tasks: BackgroundTasks,
    profile: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Trigger scan for a single device"""
    config = get_config()
    scan_profile = profile if profile in ["quick", "normal", "intensive"] else "normal"

    def run_device_scan():
        from app.database import SessionLocal
        db_session = SessionLocal()
        try:
            scanner = NetworkScanner(db_session)
            # Scan single IP (use /32 CIDR for single host)
            scan = scanner.perform_scan(
                subnet=f"{ip_address}/32",
                scan_profile=scan_profile,
                port_range=config.scanning.port_range,
                enable_os_detection=config.scanning.enable_os_detection,
                enable_service_detection=config.scanning.enable_service_detection,
                scan_type="device",  # Mark as single-device scan
            )
            # Note: Don't run change detection for single device scans
            # as it would incorrectly report other devices as "removed"
        finally:
            db_session.close()

    background_tasks.add_task(run_device_scan)
    return {"status": "started", "target": ip_address, "profile": scan_profile}


# Schedule API Endpoints
@app.get("/api/schedule")
async def get_schedules():
    """Get all scheduled scan jobs"""
    return {"jobs": get_all_schedules()}


@app.post("/api/schedule")
async def create_schedule(job: ScheduleJobCreate):
    """Create a new scheduled scan job"""
    result = add_schedule_job(job.name, job.cron, job.profile, job.enabled)
    return result


@app.put("/api/schedule/{job_id}")
async def update_schedule(job_id: str, job: ScheduleJobUpdate):
    """Update an existing scheduled scan job"""
    result = update_schedule_job(job_id, job.name, job.cron, job.profile, job.enabled)
    if result is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return result


@app.delete("/api/schedule/{job_id}")
async def delete_schedule(job_id: str):
    """Delete a scheduled scan job"""
    if not delete_schedule_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    return {"status": "deleted", "job_id": job_id}


@app.put("/api/config")
async def update_config(config_update: ConfigUpdate, request: Request, db: Session = Depends(get_db)):
    """Update configuration and save to config.yaml"""
    try:
        # Get current config
        config = get_config()

        # Track changes for audit
        old_config = {
            "subnet": config.network.subnet,
            "scan_profile": config.network.scan_profile,
            "port_range": config.scanning.port_range,
            "enable_os_detection": config.scanning.enable_os_detection
        }

        # Update network settings
        config.network.subnet = config_update.network.subnet
        config.network.scan_profile = config_update.network.scan_profile

        # Update scanning settings
        config.scanning.port_range = config_update.scanning.port_range
        config.scanning.enable_os_detection = config_update.scanning.enable_os_detection

        # Save to YAML file
        save_config(config)

        # Reload config to ensure consistency
        reload_config()

        # Log config update
        log_from_request(
            db=db,
            request=request,
            action=AuditAction.CONFIG_UPDATED,
            resource_type=ResourceType.CONFIG,
            details={
                "old": old_config,
                "new": {
                    "subnet": config.network.subnet,
                    "scan_profile": config.network.scan_profile,
                    "port_range": config.scanning.port_range,
                    "enable_os_detection": config.scanning.enable_os_detection
                }
            }
        )

        return {
            "status": "success",
            "message": "Configuration updated successfully",
            "config": {
                "network": {
                    "subnet": config.network.subnet,
                    "scan_profile": config.network.scan_profile
                },
                "scanning": {
                    "port_range": config.scanning.port_range,
                    "enable_os_detection": config.scanning.enable_os_detection
                }
            }
        }
    except Exception as e:
        logger.error(f"Failed to update config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update configuration: {str(e)}")


@app.get("/api/config")
async def get_config_endpoint():
    """Get current configuration"""
    config = get_config()
    return {
        "network": {
            "subnet": config.network.subnet,
            "scan_profile": config.network.scan_profile
        },
        "scanning": {
            "port_range": config.scanning.port_range,
            "enable_os_detection": config.scanning.enable_os_detection
        }
    }


# Integration Endpoints
@app.get("/api/integrations/cve")
async def get_cve_integration():
    """Get CVE integration settings"""
    config = get_config()
    return {
        "enabled": config.integrations.cve.enabled,
        "api_key": config.integrations.cve.api_key,
        "api_url": config.integrations.cve.api_url,
        "cache_hours": config.integrations.cve.cache_hours
    }


@app.put("/api/integrations/cve")
async def update_cve_integration(
    cve_update: CVEIntegrationUpdate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Update CVE integration settings"""
    try:
        config = get_config()

        # Track changes for audit
        old_settings = {
            "enabled": config.integrations.cve.enabled,
            "cache_hours": config.integrations.cve.cache_hours,
            "has_api_key": bool(config.integrations.cve.api_key)
        }

        # Update settings
        config.integrations.cve.enabled = cve_update.enabled
        config.integrations.cve.api_key = cve_update.api_key
        config.integrations.cve.cache_hours = cve_update.cache_hours

        # Save to YAML file
        save_config(config)

        # Reload config to ensure consistency
        reload_config()

        # Log config update
        log_from_request(
            db=db,
            request=request,
            action=AuditAction.CONFIG_UPDATED,
            resource_type=ResourceType.CONFIG,
            details={
                "integration": "cve",
                "old": old_settings,
                "new": {
                    "enabled": cve_update.enabled,
                    "cache_hours": cve_update.cache_hours,
                    "has_api_key": bool(cve_update.api_key)
                }
            }
        )

        return {
            "status": "success",
            "message": "CVE integration settings updated",
            "enabled": cve_update.enabled,
            "cache_hours": cve_update.cache_hours
        }
    except Exception as e:
        logger.error(f"Failed to update CVE integration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update settings: {str(e)}")


# UniFi Integration Endpoints
@app.get("/api/integrations/unifi")
async def get_unifi_integration():
    """Get UniFi integration settings"""
    config = get_config()
    return {
        "enabled": config.integrations.unifi.enabled,
        "controller_url": config.integrations.unifi.controller_url,
        "controller_type": config.integrations.unifi.controller_type,
        "username": config.integrations.unifi.username,
        "has_password": bool(config.integrations.unifi.password),
        "has_api_key": bool(config.integrations.unifi.api_key),
        "site_id": config.integrations.unifi.site_id,
        "verify_ssl": config.integrations.unifi.verify_ssl,
        "cache_seconds": config.integrations.unifi.cache_seconds,
        "sync_on_scan": config.integrations.unifi.sync_on_scan,
        "include_offline_clients": config.integrations.unifi.include_offline_clients,
    }


@app.put("/api/integrations/unifi")
async def update_unifi_integration(
    unifi_update: UniFiIntegrationUpdate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Update UniFi integration settings"""
    try:
        config = get_config()

        # Track changes for audit
        old_enabled = config.integrations.unifi.enabled

        # Update settings
        config.integrations.unifi.enabled = unifi_update.enabled
        config.integrations.unifi.controller_url = unifi_update.controller_url
        config.integrations.unifi.controller_type = unifi_update.controller_type
        config.integrations.unifi.site_id = unifi_update.site_id
        config.integrations.unifi.verify_ssl = unifi_update.verify_ssl
        config.integrations.unifi.cache_seconds = unifi_update.cache_seconds
        config.integrations.unifi.sync_on_scan = unifi_update.sync_on_scan
        config.integrations.unifi.include_offline_clients = unifi_update.include_offline_clients

        # Only update credentials if provided (not None)
        if unifi_update.username is not None:
            config.integrations.unifi.username = unifi_update.username
        if unifi_update.password is not None:
            config.integrations.unifi.password = unifi_update.password
        if unifi_update.api_key is not None:
            config.integrations.unifi.api_key = unifi_update.api_key

        # Save to YAML
        save_config(config)
        reload_config()

        # Log config update
        log_from_request(
            db=db,
            request=request,
            action=AuditAction.CONFIG_UPDATED,
            resource_type=ResourceType.CONFIG,
            details={
                "integration": "unifi",
                "enabled_changed": old_enabled != unifi_update.enabled,
                "new_enabled": unifi_update.enabled,
            }
        )

        return {
            "status": "success",
            "message": "UniFi integration settings updated",
            "enabled": unifi_update.enabled
        }
    except Exception as e:
        logger.error(f"Failed to update UniFi integration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update settings: {str(e)}")


@app.post("/api/integrations/unifi/test")
async def test_unifi_connection():
    """Test connection to UniFi controller"""
    from app.integrations.unifi.enricher import UniFiEnricher
    import logging

    logger = logging.getLogger(__name__)
    config = get_config()

    if not config.integrations.unifi.controller_url:
        return {
            "status": "error",
            "error_message": "No controller URL configured"
        }

    # Check authentication is configured
    has_credentials = config.integrations.unifi.username and config.integrations.unifi.password
    has_api_key = config.integrations.unifi.api_key
    if not has_credentials and not has_api_key:
        return {
            "status": "error",
            "error_message": "No authentication configured. Please set username/password or API key."
        }

    try:
        logger.info(f"Testing UniFi connection to {config.integrations.unifi.controller_url}")

        # Create enricher with current config
        enricher = UniFiEnricher(
            enabled=True,  # Force enabled for test
            controller_url=config.integrations.unifi.controller_url,
            controller_type=config.integrations.unifi.controller_type,
            username=config.integrations.unifi.username,
            password=config.integrations.unifi.password,
            api_key=config.integrations.unifi.api_key,
            site_id=config.integrations.unifi.site_id,
            verify_ssl=config.integrations.unifi.verify_ssl,
        )

        health = await enricher.test_connection()

        return {
            "status": health.status.value,
            "last_check": health.last_check.isoformat() if health.last_check else None,
            "error_message": health.error_message,
            "details": health.details
        }
    except Exception as e:
        logger.error(f"UniFi test connection failed: {e}")
        return {
            "status": "error",
            "error_message": f"Connection test failed: {str(e)}"
        }


@app.get("/api/integrations/unifi/clients")
async def get_unifi_clients():
    """Get all clients from UniFi controller"""
    from app.integrations.unifi.enricher import UniFiEnricher

    config = get_config()

    if not config.integrations.unifi.enabled:
        raise HTTPException(status_code=400, detail="UniFi integration is not enabled")

    enricher = UniFiEnricher(
        enabled=config.integrations.unifi.enabled,
        controller_url=config.integrations.unifi.controller_url,
        controller_type=config.integrations.unifi.controller_type,
        username=config.integrations.unifi.username,
        password=config.integrations.unifi.password,
        api_key=config.integrations.unifi.api_key,
        site_id=config.integrations.unifi.site_id,
        verify_ssl=config.integrations.unifi.verify_ssl,
        cache_seconds=config.integrations.unifi.cache_seconds,
        include_offline_clients=config.integrations.unifi.include_offline_clients,
    )

    try:
        data = await enricher.get_data()
        return data
    except Exception as e:
        logger.error(f"Failed to get UniFi clients: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Pi-hole Integration API
@app.get("/api/integrations/pihole")
async def get_pihole_integration():
    """Get Pi-hole integration settings"""
    config = get_config()
    return {
        "enabled": config.integrations.pihole.enabled,
        "pihole_url": config.integrations.pihole.pihole_url,
        "has_api_token": bool(config.integrations.pihole.api_token),
        "verify_ssl": config.integrations.pihole.verify_ssl,
        "cache_seconds": config.integrations.pihole.cache_seconds,
        "sync_on_scan": config.integrations.pihole.sync_on_scan,
    }


@app.put("/api/integrations/pihole")
async def update_pihole_integration(
    pihole_update: PiHoleIntegrationUpdate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Update Pi-hole integration settings"""
    try:
        config = get_config()

        # Track changes for audit
        old_enabled = config.integrations.pihole.enabled

        # Update settings
        config.integrations.pihole.enabled = pihole_update.enabled
        config.integrations.pihole.pihole_url = pihole_update.pihole_url
        config.integrations.pihole.verify_ssl = pihole_update.verify_ssl
        config.integrations.pihole.cache_seconds = pihole_update.cache_seconds
        config.integrations.pihole.sync_on_scan = pihole_update.sync_on_scan

        # Only update API token if provided (not None)
        if pihole_update.api_token is not None:
            config.integrations.pihole.api_token = pihole_update.api_token

        # Save to YAML
        save_config(config)
        reload_config()

        # Log config update
        log_from_request(
            db=db,
            request=request,
            action=AuditAction.CONFIG_UPDATED,
            resource_type=ResourceType.CONFIG,
            details={
                "integration": "pihole",
                "enabled_changed": old_enabled != pihole_update.enabled,
                "new_enabled": pihole_update.enabled,
            }
        )

        return {
            "status": "success",
            "message": "Pi-hole integration settings updated",
            "enabled": pihole_update.enabled
        }
    except Exception as e:
        logger.error(f"Failed to update Pi-hole integration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update settings: {str(e)}")


@app.post("/api/integrations/pihole/test")
async def test_pihole_connection():
    """Test connection to Pi-hole"""
    from app.integrations.pihole.enricher import PiHoleEnricher
    import logging

    logger = logging.getLogger(__name__)
    config = get_config()

    if not config.integrations.pihole.pihole_url:
        return {
            "status": "error",
            "error_message": "No Pi-hole URL configured"
        }

    try:
        logger.info(f"Testing Pi-hole connection to {config.integrations.pihole.pihole_url}")

        # Create enricher with current config
        enricher = PiHoleEnricher(
            enabled=True,  # Force enabled for test
            pihole_url=config.integrations.pihole.pihole_url,
            api_token=config.integrations.pihole.api_token,
            verify_ssl=config.integrations.pihole.verify_ssl,
        )

        health = await enricher.test_connection()

        return {
            "status": health.status.value,
            "last_check": health.last_check.isoformat() if health.last_check else None,
            "error_message": health.error_message,
            "details": health.details
        }
    except Exception as e:
        logger.error(f"Pi-hole test connection failed: {e}")
        return {
            "status": "error",
            "error_message": f"Connection test failed: {str(e)}"
        }


@app.get("/api/integrations/pihole/stats")
async def get_pihole_stats():
    """Get Pi-hole statistics"""
    from app.integrations.pihole.enricher import PiHoleEnricher

    config = get_config()

    if not config.integrations.pihole.enabled:
        raise HTTPException(status_code=400, detail="Pi-hole integration is not enabled")

    enricher = PiHoleEnricher(
        enabled=config.integrations.pihole.enabled,
        pihole_url=config.integrations.pihole.pihole_url,
        api_token=config.integrations.pihole.api_token,
        verify_ssl=config.integrations.pihole.verify_ssl,
        cache_seconds=config.integrations.pihole.cache_seconds,
    )

    try:
        data = await enricher.get_data()
        return data
    except Exception as e:
        logger.error(f"Failed to get Pi-hole stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# AdGuard Home Integration API
@app.get("/api/integrations/adguard")
async def get_adguard_integration():
    """Get AdGuard Home integration settings"""
    config = get_config()
    return {
        "enabled": config.integrations.adguard.enabled,
        "adguard_url": config.integrations.adguard.adguard_url,
        "username": config.integrations.adguard.username,
        "has_password": bool(config.integrations.adguard.password),
        "verify_ssl": config.integrations.adguard.verify_ssl,
        "cache_seconds": config.integrations.adguard.cache_seconds,
        "sync_on_scan": config.integrations.adguard.sync_on_scan,
    }


@app.put("/api/integrations/adguard")
async def update_adguard_integration(
    adguard_update: AdGuardIntegrationUpdate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Update AdGuard Home integration settings"""
    try:
        config = get_config()

        # Track changes for audit
        old_enabled = config.integrations.adguard.enabled

        # Update settings
        config.integrations.adguard.enabled = adguard_update.enabled
        config.integrations.adguard.adguard_url = adguard_update.adguard_url
        config.integrations.adguard.verify_ssl = adguard_update.verify_ssl
        config.integrations.adguard.cache_seconds = adguard_update.cache_seconds
        config.integrations.adguard.sync_on_scan = adguard_update.sync_on_scan

        # Only update credentials if provided (not None)
        if adguard_update.username is not None:
            config.integrations.adguard.username = adguard_update.username
        if adguard_update.password is not None:
            config.integrations.adguard.password = adguard_update.password

        # Save to YAML
        save_config(config)
        reload_config()

        # Log config update
        log_from_request(
            db=db,
            request=request,
            action=AuditAction.CONFIG_UPDATED,
            resource_type=ResourceType.CONFIG,
            details={
                "integration": "adguard",
                "enabled_changed": old_enabled != adguard_update.enabled,
                "new_enabled": adguard_update.enabled,
            }
        )

        return {
            "status": "success",
            "message": "AdGuard Home integration settings updated",
            "enabled": adguard_update.enabled
        }
    except Exception as e:
        logger.error(f"Failed to update AdGuard Home integration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update settings: {str(e)}")


@app.post("/api/integrations/adguard/test")
async def test_adguard_connection():
    """Test connection to AdGuard Home"""
    from app.integrations.adguard.enricher import AdGuardEnricher
    import logging

    logger = logging.getLogger(__name__)
    config = get_config()

    if not config.integrations.adguard.adguard_url:
        return {
            "status": "error",
            "error_message": "No AdGuard Home URL configured"
        }

    try:
        logger.info(f"Testing AdGuard Home connection to {config.integrations.adguard.adguard_url}")

        # Create enricher with current config
        enricher = AdGuardEnricher(
            enabled=True,  # Force enabled for test
            adguard_url=config.integrations.adguard.adguard_url,
            username=config.integrations.adguard.username,
            password=config.integrations.adguard.password,
            verify_ssl=config.integrations.adguard.verify_ssl,
        )

        health = await enricher.test_connection()

        return {
            "status": health.status.value,
            "last_check": health.last_check.isoformat() if health.last_check else None,
            "error_message": health.error_message,
            "details": health.details
        }
    except Exception as e:
        logger.error(f"AdGuard Home test connection failed: {e}")
        return {
            "status": "error",
            "error_message": f"Connection test failed: {str(e)}"
        }


@app.get("/api/integrations/adguard/stats")
async def get_adguard_stats():
    """Get AdGuard Home statistics"""
    from app.integrations.adguard.enricher import AdGuardEnricher

    config = get_config()

    if not config.integrations.adguard.enabled:
        raise HTTPException(status_code=400, detail="AdGuard Home integration is not enabled")

    enricher = AdGuardEnricher(
        enabled=config.integrations.adguard.enabled,
        adguard_url=config.integrations.adguard.adguard_url,
        username=config.integrations.adguard.username,
        password=config.integrations.adguard.password,
        verify_ssl=config.integrations.adguard.verify_ssl,
        cache_seconds=config.integrations.adguard.cache_seconds,
    )

    try:
        data = await enricher.get_data()
        return data
    except Exception as e:
        logger.error(f"Failed to get AdGuard Home stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/network/detect")
async def detect_network():
    """Detect local network configuration.

    Returns the host's IP address and suggested subnet for scanning.
    Useful for initial setup to auto-populate the scan range.
    """
    from app.utils.network_utils import get_network_info
    return get_network_info()


# Audit Log Endpoints
@app.get("/api/audit-logs", response_model=List[AuditLogResponse])
async def list_audit_logs(
    limit: int = 50,
    offset: int = 0,
    action: Optional[str] = None,
    username: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List audit logs with optional filtering"""
    query = db.query(AuditLog)

    # Apply filters
    if action:
        query = query.filter(AuditLog.action == action)
    if username:
        query = query.filter(AuditLog.username == username)

    # Order by most recent first
    logs = query.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit).all()

    return logs


@app.get("/api/audit-logs/actions")
async def list_audit_actions():
    """List all available audit action types"""
    return {
        "actions": [
            {"value": AuditAction.LOGIN_SUCCESS, "label": "Login Success"},
            {"value": AuditAction.LOGIN_FAILED, "label": "Login Failed"},
            {"value": AuditAction.LOGOUT, "label": "Logout"},
            {"value": AuditAction.SETUP_COMPLETE, "label": "Setup Complete"},
            {"value": AuditAction.API_KEY_CREATED, "label": "API Key Created"},
            {"value": AuditAction.API_KEY_REVOKED, "label": "API Key Revoked"},
            {"value": AuditAction.SCAN_STARTED, "label": "Scan Started"},
            {"value": AuditAction.SCAN_COMPLETED, "label": "Scan Completed"},
            {"value": AuditAction.DEVICE_UPDATED, "label": "Device Updated"},
            {"value": AuditAction.CONFIG_UPDATED, "label": "Config Updated"},
        ]
    }


# API Key Management Endpoints
@app.get("/api/keys", response_model=List[APIKeyResponse])
async def list_api_keys(request: Request, db: Session = Depends(get_db)):
    """List all API keys for the current user"""
    current_user = get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    keys = db.query(APIKey).filter(APIKey.user_id == user.id).order_by(APIKey.created_at.desc()).all()
    return keys


@app.post("/api/keys", response_model=APIKeyCreatedResponse)
async def create_api_key(
    key_data: APIKeyCreateRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Create a new API key. The full key is only shown once!"""
    current_user = get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate the API key
    plain_key = generate_api_key()
    key_hash = hash_api_key(plain_key)
    key_prefix = get_api_key_prefix(plain_key)

    # Calculate expiration if specified
    expires_at = None
    if key_data.expires_in_days:
        from datetime import timedelta
        expires_at = datetime.utcnow() + timedelta(days=key_data.expires_in_days)

    # Create the API key record
    api_key = APIKey(
        user_id=user.id,
        name=key_data.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        expires_at=expires_at
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    logger.info(f"API key '{key_data.name}' created for user {user.username}")

    # Log API key creation
    log_action(
        db=db,
        action=AuditAction.API_KEY_CREATED,
        user_id=user.id,
        username=user.username,
        resource_type=ResourceType.API_KEY,
        resource_id=api_key.id,
        details={"name": key_data.name, "expires_at": expires_at.isoformat() if expires_at else None},
        request=request
    )

    return APIKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        key=plain_key,
        key_prefix=key_prefix,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at
    )


@app.delete("/api/keys/{key_id}")
async def revoke_api_key(
    key_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    """Revoke an API key"""
    current_user = get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    api_key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.user_id == current_user["user_id"]
    ).first()

    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    api_key.is_revoked = True
    db.commit()

    logger.info(f"API key '{api_key.name}' revoked")

    # Log API key revocation
    log_action(
        db=db,
        action=AuditAction.API_KEY_REVOKED,
        user_id=current_user["user_id"],
        username=current_user["username"],
        resource_type=ResourceType.API_KEY,
        resource_id=key_id,
        details={"name": api_key.name},
        request=request
    )

    return {"status": "revoked", "id": key_id, "name": api_key.name}


# Settings UI Page
@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, db: Session = Depends(get_db)):
    """Settings page"""
    config = get_config()
    schedules = get_all_schedules()
    current_user = get_current_user(request)

    # Get API keys for current user
    api_keys = []
    if current_user:
        api_key_records = db.query(APIKey).filter(
            APIKey.user_id == current_user["user_id"]
        ).order_by(APIKey.created_at.desc()).all()
        # Convert to serializable dicts
        api_keys = [
            {
                "id": key.id,
                "name": key.name,
                "key_prefix": key.key_prefix,
                "created_at": key.created_at.isoformat() if key.created_at else None,
                "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
                "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                "is_revoked": key.is_revoked
            }
            for key in api_key_records
        ]

    return templates.TemplateResponse("settings.html", {
        "request": request,
        "active_page": "settings",
        "config": config,
        "schedules": schedules,
        "current_user": current_user,
        "api_keys": api_keys
    })


# Integration Settings Pages
@app.get("/settings/integrations", response_class=HTMLResponse)
async def integrations_page(request: Request):
    """Integrations overview page"""
    config = get_config()
    return templates.TemplateResponse("settings_integrations.html", {
        "request": request,
        "active_page": "settings",
        "config": config,
        "current_user": get_current_user(request)
    })


@app.get("/settings/integrations/unifi", response_class=HTMLResponse)
async def integration_unifi_page(request: Request):
    """UniFi integration settings page"""
    config = get_config()
    return templates.TemplateResponse("settings_integration_unifi.html", {
        "request": request,
        "active_page": "settings",
        "config": config,
        "current_user": get_current_user(request)
    })


@app.get("/settings/integrations/pihole", response_class=HTMLResponse)
async def integration_pihole_page(request: Request):
    """Pi-hole integration settings page"""
    config = get_config()
    return templates.TemplateResponse("settings_integration_pihole.html", {
        "request": request,
        "active_page": "settings",
        "config": config,
        "current_user": get_current_user(request)
    })


@app.get("/settings/integrations/adguard", response_class=HTMLResponse)
async def integration_adguard_page(request: Request):
    """AdGuard Home integration settings page"""
    config = get_config()
    return templates.TemplateResponse("settings_integration_adguard.html", {
        "request": request,
        "active_page": "settings",
        "config": config,
        "current_user": get_current_user(request)
    })


@app.get("/settings/integrations/cve", response_class=HTMLResponse)
async def integration_cve_page(request: Request):
    """CVE Database integration settings page"""
    config = get_config()
    return templates.TemplateResponse("settings_integration_cve.html", {
        "request": request,
        "active_page": "settings",
        "config": config,
        "current_user": get_current_user(request)
    })


@app.post("/api/integrations/cve/test")
async def test_cve_connection():
    """Test connection to NVD API"""
    import aiohttp

    config = get_config()

    try:
        # Test the NVD API with a simple request
        headers = {}
        if config.integrations.cve.api_key:
            headers["apiKey"] = config.integrations.cve.api_key

        async with aiohttp.ClientSession() as session:
            # Test with a simple CVE lookup
            async with session.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    return {
                        "status": "connected",
                        "details": {
                            "has_api_key": bool(config.integrations.cve.api_key)
                        }
                    }
                else:
                    return {
                        "status": "error",
                        "error_message": f"API returned status {response.status}"
                    }
    except Exception as e:
        logger.error(f"CVE API test failed: {e}")
        return {
            "status": "error",
            "error_message": f"Connection failed: {str(e)}"
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
