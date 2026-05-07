"""Scan management routes."""
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Request, BackgroundTasks, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models import Scan, Device
from app.config import get_config
from app.scanner import NetworkScanner
from app.utils.change_detector import ChangeDetector
from app.audit import log_from_request, AuditAction, ResourceType
from app.schemas import ScanRequest, ScanResponse, DeviceUpdate
from app.schemas import PortResponse

logger = logging.getLogger(__name__)
router = APIRouter()


class DeviceResponse:
    pass


# Inline response model used by list_scan_devices
from pydantic import BaseModel


class _DeviceResponse(BaseModel):
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


@router.post("/api/scans", response_model=ScanResponse)
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


@router.get("/api/scans", response_model=List[ScanResponse])
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


@router.get("/api/scans/{scan_id}", response_model=ScanResponse)
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


@router.get("/api/scans/{scan_id}/devices", response_model=List[_DeviceResponse])
async def list_scan_devices(scan_id: int, db: Session = Depends(get_db)):
    """List devices from a specific scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return [
        _DeviceResponse(
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


@router.get("/api/scan/status")
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


@router.post("/api/scan/trigger")
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
                subnets=config.network.subnets,
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


@router.post("/api/scan/device/{ip_address}")
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
