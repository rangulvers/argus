"""Configuration and schedule management routes."""
import logging
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import get_config, save_config, reload_config
from app.scheduler import (
    get_all_schedules, add_schedule_job,
    update_schedule_job, delete_schedule_job
)
from app.audit import log_from_request, AuditAction, ResourceType
from app.schemas import ConfigUpdate, ScheduleJobCreate, ScheduleJobUpdate

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/schedule")
async def get_schedules():
    """Get all scheduled scan jobs"""
    return {"jobs": get_all_schedules()}


@router.post("/api/schedule")
async def create_schedule(job: ScheduleJobCreate):
    """Create a new scheduled scan job"""
    result = add_schedule_job(job.name, job.cron, job.profile, job.enabled)
    return result


@router.put("/api/schedule/{job_id}")
async def update_schedule(job_id: str, job: ScheduleJobUpdate):
    """Update an existing scheduled scan job"""
    result = update_schedule_job(job_id, job.name, job.cron, job.profile, job.enabled)
    if result is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return result


@router.delete("/api/schedule/{job_id}")
async def delete_schedule(job_id: str):
    """Delete a scheduled scan job"""
    if not delete_schedule_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    return {"status": "deleted", "job_id": job_id}


@router.put("/api/config")
async def update_config(config_update: ConfigUpdate, request: Request, db: Session = Depends(get_db)):
    """Update configuration and save to config.yaml"""
    try:
        # Get current config
        config = get_config()

        # Track changes for audit
        old_config = {
            "subnets": config.network.subnets,
            "scan_profile": config.network.scan_profile,
            "port_range": config.scanning.port_range,
            "enable_os_detection": config.scanning.enable_os_detection
        }

        net = config_update.network
        # Update network settings — subnets takes priority; fall back to single subnet for backward compat
        if net.subnets is not None:
            config.network.subnets = net.subnets
        elif net.subnet is not None:
            config.network.subnets = [net.subnet]
        config.network.scan_profile = net.scan_profile

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
                    "subnets": config.network.subnets,
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
                    "subnets": config.network.subnets,
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


@router.get("/api/config")
async def get_config_endpoint():
    """Get current configuration"""
    config = get_config()
    return {
        "network": {
            "subnets": config.network.subnets,
            "subnet": config.network.subnet,
            "scan_profile": config.network.scan_profile
        },
        "scanning": {
            "port_range": config.scanning.port_range,
            "enable_os_detection": config.scanning.enable_os_detection
        }
    }
