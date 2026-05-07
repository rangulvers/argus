"""HTML page routes."""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import desc

from app.database import get_db
from app.models import Scan, Device, Change, APIKey
from app.auth import get_current_user
from app.config import get_config
from app.scheduler import get_all_schedules
from app.templates_config import templates

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    """Dashboard home page"""
    # Get latest network scan (not single-device scans)
    latest_scan = (
        db.query(Scan)
        .options(selectinload(Scan.devices).selectinload(Device.ports))
        .filter(
            Scan.status == "completed",
            Scan.scan_type == "network"
        )
        .order_by(desc(Scan.started_at))
        .first()
    )

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


@router.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request, scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Devices list page"""
    # Only show network scans in dropdown (not single-device scans)
    scans = db.query(Scan).filter(
        Scan.status == "completed",
        Scan.scan_type == "network"
    ).order_by(desc(Scan.started_at)).limit(20).all()

    # Get selected scan or latest network scan
    if scan_id:
        current_scan = (
            db.query(Scan)
            .options(selectinload(Scan.devices).selectinload(Device.ports))
            .filter(Scan.id == scan_id)
            .first()
        )
    else:
        current_scan = (
            db.query(Scan)
            .options(selectinload(Scan.devices).selectinload(Device.ports))
            .filter(Scan.id == scans[0].id)
            .first()
        ) if scans else None

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


@router.get("/devices/{device_id}", response_class=HTMLResponse)
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


@router.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request, db: Session = Depends(get_db)):
    """Scan history page"""
    scans = db.query(Scan).order_by(desc(Scan.started_at)).limit(50).all()

    return templates.TemplateResponse("scans.html", {
        "request": request,
        "active_page": "scans",
        "scans": scans,
        "current_user": get_current_user(request)
    })


@router.get("/visualization", response_class=HTMLResponse)
async def visualization_page(request: Request, db: Session = Depends(get_db)):
    """Network visualization page"""
    scans = db.query(Scan).filter(Scan.status == "completed").order_by(desc(Scan.completed_at)).limit(20).all()

    return templates.TemplateResponse("visualization.html", {
        "request": request,
        "active_page": "visualization",
        "scans": scans,
        "current_user": get_current_user(request)
    })


@router.get("/changes", response_class=HTMLResponse)
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


@router.get("/compare", response_class=HTMLResponse)
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


@router.get("/settings", response_class=HTMLResponse)
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


@router.get("/settings/integrations", response_class=HTMLResponse)
async def integrations_page(request: Request):
    """Integrations overview page"""
    config = get_config()
    return templates.TemplateResponse("settings_integrations.html", {
        "request": request,
        "active_page": "settings",
        "config": config,
        "current_user": get_current_user(request)
    })


@router.get("/settings/integrations/unifi", response_class=HTMLResponse)
async def integration_unifi_page(request: Request):
    """UniFi integration settings page"""
    config = get_config()
    return templates.TemplateResponse("settings_integration_unifi.html", {
        "request": request,
        "active_page": "settings",
        "config": config,
        "current_user": get_current_user(request)
    })


@router.get("/settings/integrations/pihole", response_class=HTMLResponse)
async def integration_pihole_page(request: Request):
    """Pi-hole integration settings page"""
    config = get_config()
    return templates.TemplateResponse("settings_integration_pihole.html", {
        "request": request,
        "active_page": "settings",
        "config": config,
        "current_user": get_current_user(request)
    })


@router.get("/settings/integrations/adguard", response_class=HTMLResponse)
async def integration_adguard_page(request: Request):
    """AdGuard Home integration settings page"""
    config = get_config()
    return templates.TemplateResponse("settings_integration_adguard.html", {
        "request": request,
        "active_page": "settings",
        "config": config,
        "current_user": get_current_user(request)
    })


@router.get("/settings/integrations/cve", response_class=HTMLResponse)
async def integration_cve_page(request: Request):
    """CVE Database integration settings page"""
    config = get_config()
    return templates.TemplateResponse("settings_integration_cve.html", {
        "request": request,
        "active_page": "settings",
        "config": config,
        "current_user": get_current_user(request)
    })
