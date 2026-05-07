"""Backup, restore, retention, and export routes."""
import io
import csv
import logging
import zipfile
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import desc

from app.database import get_db
from app.models import Scan, Device
from app.auth import get_current_user
from app.config import get_config
from app.scheduler import run_retention_cleanup

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/backup")
async def download_backup(request: Request, db: Session = Depends(get_db)):
    """Download a zip containing the database and config."""
    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login")

    db_path = Path("./data/argus.db")
    config_path = Path("./config.yaml")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if db_path.exists():
            zf.write(db_path, "argus.db")
        if config_path.exists():
            zf.write(config_path, "config.yaml")
    buf.seek(0)

    filename = f"argus-backup-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.post("/api/restore")
async def restore_backup(request: Request, db: Session = Depends(get_db)):
    """Restore database and config from a backup zip."""
    current_user = get_current_user(request)
    if not current_user:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    body = await request.body()
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            names = zf.namelist()
            if "argus.db" in names:
                Path("./data").mkdir(exist_ok=True)
                zf.extract("argus.db", "./data/")
                logger.info("Database restored from backup")
            if "config.yaml" in names:
                zf.extract("config.yaml", "./")
                logger.info("Config restored from backup")
        return {"success": True, "restored": names}
    except zipfile.BadZipFile:
        return JSONResponse(status_code=400, content={"error": "Invalid backup file"})


@router.post("/api/retention/cleanup")
async def trigger_retention_cleanup(request: Request, db: Session = Depends(get_db)):
    """Manually trigger retention cleanup."""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    current_user = get_current_user(request)
    if not current_user:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    config = get_config()

    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as pool:
        deleted = await loop.run_in_executor(
            pool,
            run_retention_cleanup,
            config.database.path,
            config.database.retention_days,
        )

    logger.info("Manual retention cleanup: deleted %d scans", deleted)
    return {"success": True, "deleted_scans": deleted}


@router.get("/api/stats/db")
async def get_db_stats(request: Request, db: Session = Depends(get_db)):
    """Get database size and scan count stats."""
    import os

    current_user = get_current_user(request)
    if not current_user:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    config = get_config()
    db_path = config.database.path
    db_size_bytes = os.path.getsize(db_path) if os.path.exists(db_path) else 0

    total_scans = db.query(Scan).count()
    total_devices = db.query(Device).count()

    return {
        "db_size_bytes": db_size_bytes,
        "db_size_mb": round(db_size_bytes / (1024 * 1024), 2),
        "total_scans": total_scans,
        "total_devices": total_devices,
        "retention_days": config.database.retention_days,
    }


@router.get("/api/export/devices.csv")
async def export_devices_csv(request: Request, db: Session = Depends(get_db)):
    """Export all devices as CSV."""
    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login")

    latest_scan = db.query(Scan).order_by(desc(Scan.id)).first()
    if not latest_scan:
        devices = []
    else:
        devices = (
            db.query(Device)
            .filter(Device.scan_id == latest_scan.id)
            .options(selectinload(Device.ports))
            .order_by(Device.ip_address)
            .all()
        )

    buf = io.StringIO()
    fieldnames = ["ip_address", "mac_address", "hostname", "vendor", "os_name", "risk_score", "is_trusted", "open_ports", "last_seen"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for d in devices:
        writer.writerow({
            "ip_address": d.ip_address,
            "mac_address": d.mac_address or "",
            "hostname": d.hostname or "",
            "vendor": d.vendor or "",
            "os_name": d.os_name or "",
            "risk_score": d.risk_score or 0,
            "is_trusted": d.is_trusted,
            "open_ports": ",".join(str(p.port_number) for p in (d.ports or [])),
            "last_seen": d.last_seen.isoformat() if d.last_seen else "",
        })

    content = buf.getvalue().encode("utf-8")
    return StreamingResponse(
        io.BytesIO(content),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=argus-devices.csv"},
    )


@router.get("/api/export/devices.json")
async def export_devices_json(request: Request, db: Session = Depends(get_db)):
    """Export all devices as JSON."""
    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login")

    latest_scan = db.query(Scan).order_by(desc(Scan.id)).first()
    if not latest_scan:
        return JSONResponse(content=[])

    devices = (
        db.query(Device)
        .filter(Device.scan_id == latest_scan.id)
        .options(selectinload(Device.ports))
        .order_by(Device.ip_address)
        .all()
    )

    result = []
    for d in devices:
        result.append({
            "ip_address": d.ip_address,
            "mac_address": d.mac_address,
            "hostname": d.hostname,
            "vendor": d.vendor,
            "os_name": d.os_name,
            "risk_score": d.risk_score,
            "is_trusted": d.is_trusted,
            "device_type": d.device_type,
            "open_ports": [{"port": p.port_number, "service": p.service_name, "protocol": p.protocol} for p in (d.ports or [])],
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        })

    return JSONResponse(
        content=result,
        headers={"Content-Disposition": "attachment; filename=argus-devices.json"},
    )
