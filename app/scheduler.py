"""Scheduled scan management using APScheduler"""

import logging
import yaml
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

# Config file path
CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"

# Global scheduler instance
_scheduler: Optional[BackgroundScheduler] = None
_job_id = "scheduled_network_scan"


def get_scheduler() -> BackgroundScheduler:
    """Get or create the scheduler instance"""
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler()
        _scheduler.start()
        logger.info("Scheduler started")
    return _scheduler


def load_schedule_config() -> Dict[str, Any]:
    """Load schedule configuration from config.yaml"""
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, 'r') as f:
                config = yaml.safe_load(f) or {}
                return {
                    "enabled": config.get("schedule", {}).get("enabled", False),
                    "cron": config.get("schedule", {}).get("cron", "0 2 * * 0"),
                    "profile": config.get("schedule", {}).get("profile", "normal"),
                }
    except Exception as e:
        logger.error(f"Failed to load schedule config: {e}")

    return {"enabled": False, "cron": "0 2 * * 0", "profile": "normal"}


def save_schedule_config(enabled: bool, cron: str, profile: str) -> bool:
    """Save schedule configuration to config.yaml"""
    try:
        config = {}
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, 'r') as f:
                config = yaml.safe_load(f) or {}

        if "schedule" not in config:
            config["schedule"] = {}

        config["schedule"]["enabled"] = enabled
        config["schedule"]["cron"] = cron
        config["schedule"]["profile"] = profile

        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)

        logger.info(f"Schedule config saved: enabled={enabled}, cron={cron}, profile={profile}")
        return True
    except Exception as e:
        logger.error(f"Failed to save schedule config: {e}")
        return False


def run_scheduled_scan():
    """Execute a scheduled network scan"""
    from app.database import SessionLocal
    from app.scanner import NetworkScanner
    from app.utils.change_detector import ChangeDetector
    from app.config import get_config

    logger.info("Starting scheduled network scan")
    config = get_config()
    schedule_config = load_schedule_config()

    db = SessionLocal()
    try:
        scanner = NetworkScanner(db)
        scan = scanner.perform_scan(
            subnet=config.network.subnet,
            scan_profile=schedule_config.get("profile", "normal"),
            port_range=config.scanning.port_range,
            enable_os_detection=config.scanning.enable_os_detection,
            enable_service_detection=config.scanning.enable_service_detection,
            scan_type="network",
        )

        if scan.status == "completed":
            detector = ChangeDetector(db)
            detector.detect_changes(scan.id)
            logger.info(f"Scheduled scan completed: {scan.devices_found} devices found")
    except Exception as e:
        logger.error(f"Scheduled scan failed: {e}")
    finally:
        db.close()


def parse_cron_expression(cron: str) -> Dict[str, str]:
    """Parse a cron expression into APScheduler trigger kwargs"""
    parts = cron.split()
    if len(parts) != 5:
        raise ValueError(f"Invalid cron expression: {cron}")

    return {
        "minute": parts[0],
        "hour": parts[1],
        "day": parts[2],
        "month": parts[3],
        "day_of_week": parts[4],
    }


def update_scheduled_job(enabled: bool, cron: str, profile: str) -> Dict[str, Any]:
    """Update the scheduled scan job"""
    scheduler = get_scheduler()

    # Remove existing job if any
    if scheduler.get_job(_job_id):
        scheduler.remove_job(_job_id)
        logger.info("Removed existing scheduled job")

    # Save to config
    save_schedule_config(enabled, cron, profile)

    if not enabled:
        return {"status": "disabled", "next_run": None}

    try:
        cron_kwargs = parse_cron_expression(cron)
        trigger = CronTrigger(**cron_kwargs)

        job = scheduler.add_job(
            run_scheduled_scan,
            trigger=trigger,
            id=_job_id,
            name="Network Scan",
            replace_existing=True,
        )

        next_run = job.next_run_time.isoformat() if job.next_run_time else None
        logger.info(f"Scheduled job updated: next run at {next_run}")

        return {"status": "enabled", "next_run": next_run}
    except Exception as e:
        logger.error(f"Failed to schedule job: {e}")
        return {"status": "error", "error": str(e)}


def get_schedule_status() -> Dict[str, Any]:
    """Get current schedule status"""
    config = load_schedule_config()
    scheduler = get_scheduler()
    job = scheduler.get_job(_job_id)

    return {
        "enabled": config["enabled"],
        "cron": config["cron"],
        "profile": config["profile"],
        "next_run": job.next_run_time.isoformat() if job and job.next_run_time else None,
        "job_active": job is not None,
    }


def init_scheduler():
    """Initialize scheduler with saved configuration"""
    config = load_schedule_config()
    if config["enabled"]:
        result = update_scheduled_job(True, config["cron"], config["profile"])
        logger.info(f"Scheduler initialized: {result}")
    else:
        logger.info("Scheduler initialized but no job scheduled (disabled)")
    return get_scheduler()
