"""Argus FastAPI Application"""

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from datetime import datetime
import logging

from app.database import get_db, init_db
from app.models import Scan, Device, Port, Change, DeviceHistory, User
from app.scanner import NetworkScanner
from app.utils.change_detector import ChangeDetector
from app.config import get_config, save_config, reload_config
from app.scheduler import (
    init_scheduler, get_all_schedules, add_schedule_job,
    update_schedule_job, delete_schedule_job
)
from app.auth import (
    hash_password, verify_password, set_session_cookie,
    clear_session_cookie, get_current_user, requires_auth
)
from app.version import get_version, get_build_info
from app.utils.device_icons import detect_device_type, get_device_icon_info
from pydantic import BaseModel

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Argus",
    description="The All-Seeing Network Monitor",
    version=get_version()
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
    path = request.url.path

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
                return RedirectResponse(url="/setup", status_code=302)
            return await call_next(request)

        # Check if user is authenticated
        current_user = get_current_user(request)
        if not current_user:
            # Not logged in - redirect to login
            return RedirectResponse(url="/login", status_code=302)

        # User is authenticated - continue
        return await call_next(request)
    finally:
        db.close()


# Pydantic models for API
class ScanRequest(BaseModel):
    subnet: Optional[str] = None
    scan_profile: Optional[str] = "normal"
    port_range: Optional[str] = None
    detect_changes: bool = True


class ScheduleJobCreate(BaseModel):
    name: str
    cron: str
    profile: str = "normal"
    enabled: bool = True


class ScheduleJobUpdate(BaseModel):
    name: str
    cron: str
    profile: str = "normal"
    enabled: bool = True


class NetworkConfigUpdate(BaseModel):
    subnet: str
    scan_profile: str


class ScanningConfigUpdate(BaseModel):
    port_range: str
    enable_os_detection: bool


class ConfigUpdate(BaseModel):
    network: NetworkConfigUpdate
    scanning: ScanningConfigUpdate


class DeviceUpdate(BaseModel):
    label: Optional[str] = None
    notes: Optional[str] = None
    is_trusted: Optional[bool] = None
    zone: Optional[str] = None


class ScanResponse(BaseModel):
    id: int
    started_at: datetime
    completed_at: Optional[datetime]
    status: str
    subnet: str
    devices_found: int
    scan_profile: str

    class Config:
        from_attributes = True


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


class PortResponse(BaseModel):
    port_number: int
    protocol: str
    state: str
    service_name: Optional[str]
    service_version: Optional[str]

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

    # Get the latest completed scan for risk assessment and timestamp
    latest_scan = db.query(Scan).filter(
        Scan.status == "completed"
    ).order_by(desc(Scan.completed_at)).first()

    # Calculate risk stats from the latest scan's devices
    devices_at_risk = 0
    critical_devices = 0
    high_risk_devices = 0

    if latest_scan:
        devices = db.query(Device).filter(Device.scan_id == latest_scan.id).all()
        for device in devices:
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
        "last_scan": latest_scan.completed_at.isoformat() if latest_scan and latest_scan.completed_at else None
    }


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
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    remember: bool = Form(False),
    db: Session = Depends(get_db)
):
    """Process login form"""
    # Find user
    user = db.query(User).filter(User.username == username).first()

    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password",
            "username": username
        })

    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    # Create response with session cookie
    response = RedirectResponse(url="/", status_code=302)
    set_session_cookie(response, user.id, user.username, remember)
    return response


@app.get("/logout")
async def logout():
    """Logout and clear session"""
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

    # Create response with session cookie (auto-login)
    response = RedirectResponse(url="/", status_code=302)
    set_session_cookie(response, user.id, user.username, remember=True)
    return response


# API Endpoints
@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Trigger a new network scan"""
    config = get_config()

    subnet = scan_request.subnet or config.network.subnet
    scan_profile = scan_request.scan_profile or config.network.scan_profile
    port_range = scan_request.port_range or config.scanning.port_range

    logger.info(f"Starting scan: {subnet}, profile: {scan_profile}")

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
async def update_device(device_id: int, update: DeviceUpdate, db: Session = Depends(get_db)):
    """Update device properties (label, notes, is_trusted, zone)"""
    device = db.query(Device).filter(Device.id == device_id).first()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

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
async def update_config(config_update: ConfigUpdate):
    """Update configuration and save to config.yaml"""
    try:
        # Get current config
        config = get_config()

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


# Settings UI Page
@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page"""
    config = get_config()
    schedules = get_all_schedules()

    return templates.TemplateResponse("settings.html", {
        "request": request,
        "active_page": "settings",
        "config": config,
        "schedules": schedules,
        "current_user": get_current_user(request)
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
