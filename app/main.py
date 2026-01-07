"""Argus FastAPI Application"""

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from datetime import datetime
import logging

from app.database import get_db, init_db
from app.models import Scan, Device, Port, Change, DeviceHistory
from app.scanner import NetworkScanner
from app.utils.change_detector import ChangeDetector
from app.config import get_config
from pydantic import BaseModel

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Argus",
    description="The All-Seeing Network Monitor",
    version="0.1.0"
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    init_db()
    logger.info("Database initialized")


# Pydantic models for API
class ScanRequest(BaseModel):
    subnet: Optional[str] = None
    scan_profile: Optional[str] = "normal"
    port_range: Optional[str] = None
    detect_changes: bool = True


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
    # Get latest scan
    latest_scan = db.query(Scan).filter(Scan.status == "completed").order_by(desc(Scan.started_at)).first()

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
        "recent_changes": recent_changes
    })


@app.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request, scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Devices list page"""
    scans = db.query(Scan).filter(Scan.status == "completed").order_by(desc(Scan.started_at)).limit(20).all()

    # Get selected scan or latest
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
        "selected_scan_id": selected_scan_id
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
        "device": device
    })


@app.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request, db: Session = Depends(get_db)):
    """Scan history page"""
    scans = db.query(Scan).order_by(desc(Scan.started_at)).limit(50).all()

    return templates.TemplateResponse("scans.html", {
        "request": request,
        "active_page": "scans",
        "scans": scans
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
        "selected_scan_id": scan_id
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
        "comparison": comparison
    })


@app.get("/api/scan/status")
async def get_scan_status(db: Session = Depends(get_db)):
    """Check if there are any running scans"""
    running_scan = db.query(Scan).filter(Scan.status == "running").first()

    if running_scan:
        return {
            "scanning": True,
            "scan_id": running_scan.id,
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
            )
            if scan.status == "completed":
                detector = ChangeDetector(db_session)
                detector.detect_changes(scan.id)
        finally:
            db_session.close()

    background_tasks.add_task(run_device_scan)
    return {"status": "started", "target": ip_address, "profile": scan_profile}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
