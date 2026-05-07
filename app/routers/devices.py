"""Device management routes."""
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models import Device, DeviceHistory
from app.audit import log_from_request, AuditAction, ResourceType
from app.schemas import DeviceUpdate, PortResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/devices/{device_id}/ports", response_model=List[PortResponse])
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


@router.put("/api/devices/{device_id}")
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


@router.get("/api/zones")
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


@router.get("/api/device-history")
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
