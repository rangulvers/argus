"""Scheduled scan management using APScheduler - supports multiple scan jobs"""

import logging
import yaml
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

# Config file path
CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"

# Global scheduler instance
_scheduler: Optional[BackgroundScheduler] = None


def get_scheduler() -> BackgroundScheduler:
    """Get or create the scheduler instance"""
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler()
        _scheduler.start()
        logger.info("Scheduler started")
    return _scheduler


def load_schedule_config() -> List[Dict[str, Any]]:
    """Load schedule jobs from config.yaml"""
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, 'r') as f:
                config = yaml.safe_load(f) or {}
                jobs = config.get("schedule", {}).get("jobs", [])
                # Ensure each job has an ID
                for job in jobs:
                    if "id" not in job:
                        job["id"] = str(uuid.uuid4())[:8]
                return jobs
    except Exception as e:
        logger.error(f"Failed to load schedule config: {e}")
    return []


def save_schedule_config(jobs: List[Dict[str, Any]]) -> bool:
    """Save schedule jobs to config.yaml"""
    try:
        config = {}
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, 'r') as f:
                config = yaml.safe_load(f) or {}

        if "schedule" not in config:
            config["schedule"] = {}

        config["schedule"]["jobs"] = jobs

        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        logger.info(f"Schedule config saved: {len(jobs)} jobs")
        return True
    except Exception as e:
        logger.error(f"Failed to save schedule config: {e}")
        return False


def run_scheduled_scan(profile: str, job_name: str):
    """Execute a scheduled network scan"""
    from app.database import SessionLocal
    from app.scanner import NetworkScanner
    from app.utils.change_detector import ChangeDetector
    from app.config import get_config

    logger.info(f"Starting scheduled scan: {job_name} (profile: {profile})")
    config = get_config()

    db = SessionLocal()
    try:
        scanner = NetworkScanner(db)
        scan = scanner.perform_scan(
            subnet=config.network.subnet,
            scan_profile=profile,
            port_range=config.scanning.port_range,
            enable_os_detection=config.scanning.enable_os_detection,
            enable_service_detection=config.scanning.enable_service_detection,
            scan_type="network",
        )

        if scan.status == "completed":
            detector = ChangeDetector(db)
            detector.detect_changes(scan.id)
            logger.info(f"Scheduled scan '{job_name}' completed: {scan.devices_found} devices found")
    except Exception as e:
        logger.error(f"Scheduled scan '{job_name}' failed: {e}")
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


def get_job_id(job_id: str) -> str:
    """Get the APScheduler job ID for a config job"""
    return f"scan_job_{job_id}"


def sync_scheduler_jobs():
    """Sync APScheduler jobs with config"""
    scheduler = get_scheduler()
    jobs = load_schedule_config()

    # Get current APScheduler job IDs
    current_job_ids = {job.id for job in scheduler.get_jobs()}
    config_job_ids = {get_job_id(job["id"]) for job in jobs if job.get("enabled", False)}

    # Remove jobs that are no longer in config or disabled
    for job_id in current_job_ids:
        if job_id.startswith("scan_job_") and job_id not in config_job_ids:
            scheduler.remove_job(job_id)
            logger.info(f"Removed job: {job_id}")

    # Add/update jobs from config
    for job in jobs:
        if not job.get("enabled", False):
            continue

        job_id = get_job_id(job["id"])
        try:
            cron_kwargs = parse_cron_expression(job["cron"])
            trigger = CronTrigger(**cron_kwargs)

            if scheduler.get_job(job_id):
                scheduler.reschedule_job(job_id, trigger=trigger)
                logger.info(f"Updated job: {job['name']}")
            else:
                scheduler.add_job(
                    run_scheduled_scan,
                    trigger=trigger,
                    id=job_id,
                    name=job.get("name", "Scheduled Scan"),
                    args=[job.get("profile", "normal"), job.get("name", "Scheduled Scan")],
                    replace_existing=True,
                )
                logger.info(f"Added job: {job['name']}")
        except Exception as e:
            logger.error(f"Failed to schedule job '{job.get('name')}': {e}")


def add_schedule_job(name: str, cron: str, profile: str, enabled: bool = True) -> Dict[str, Any]:
    """Add a new scheduled scan job"""
    jobs = load_schedule_config()

    new_job = {
        "id": str(uuid.uuid4())[:8],
        "name": name,
        "cron": cron,
        "profile": profile,
        "enabled": enabled,
    }
    jobs.append(new_job)

    save_schedule_config(jobs)
    sync_scheduler_jobs()

    return get_job_status(new_job["id"])


def update_schedule_job(job_id: str, name: str, cron: str, profile: str, enabled: bool) -> Optional[Dict[str, Any]]:
    """Update an existing scheduled scan job"""
    jobs = load_schedule_config()

    for job in jobs:
        if job["id"] == job_id:
            job["name"] = name
            job["cron"] = cron
            job["profile"] = profile
            job["enabled"] = enabled
            break
    else:
        return None

    save_schedule_config(jobs)
    sync_scheduler_jobs()

    return get_job_status(job_id)


def delete_schedule_job(job_id: str) -> bool:
    """Delete a scheduled scan job"""
    jobs = load_schedule_config()
    original_count = len(jobs)

    jobs = [j for j in jobs if j["id"] != job_id]

    if len(jobs) == original_count:
        return False

    save_schedule_config(jobs)
    sync_scheduler_jobs()

    return True


def get_job_status(job_id: str) -> Optional[Dict[str, Any]]:
    """Get status of a specific job"""
    jobs = load_schedule_config()
    scheduler = get_scheduler()

    for job in jobs:
        if job["id"] == job_id:
            apscheduler_job = scheduler.get_job(get_job_id(job_id))
            return {
                **job,
                "next_run": apscheduler_job.next_run_time.isoformat() if apscheduler_job and apscheduler_job.next_run_time else None,
            }
    return None


def get_all_schedules() -> List[Dict[str, Any]]:
    """Get all scheduled jobs with their status"""
    jobs = load_schedule_config()
    scheduler = get_scheduler()
    result = []

    for job in jobs:
        apscheduler_job = scheduler.get_job(get_job_id(job["id"]))
        result.append({
            **job,
            "next_run": apscheduler_job.next_run_time.isoformat() if apscheduler_job and apscheduler_job.next_run_time else None,
        })

    return result


def migrate_legacy_schedule():
    """Migrate legacy network.scan_schedule to schedule.jobs if no jobs exist."""
    jobs = load_schedule_config()
    if jobs:
        return  # Already has jobs, nothing to migrate

    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, 'r') as f:
                config = yaml.safe_load(f) or {}

            legacy_cron = config.get("network", {}).get("scan_schedule")
            legacy_profile = config.get("network", {}).get("scan_profile", "normal")

            if legacy_cron:
                new_job = {
                    "id": str(uuid.uuid4())[:8],
                    "name": "Scheduled Scan (migrated)",
                    "cron": legacy_cron,
                    "profile": legacy_profile,
                    "enabled": True,
                }
                save_schedule_config([new_job])
                logger.info(
                    f"Migrated legacy scan_schedule '{legacy_cron}' (profile: {legacy_profile}) "
                    f"to schedule.jobs as '{new_job['name']}' (id: {new_job['id']})"
                )
    except Exception as e:
        logger.error(f"Failed to migrate legacy schedule: {e}")


def run_retention_cleanup(db_path: str, retention_days: int) -> int:
    """Delete scans older than retention_days and their related data."""
    import sqlite3
    from datetime import datetime, timedelta

    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    logger.info(f"Running retention cleanup: deleting scans older than {cutoff.isoformat()} ({retention_days} days)")

    with sqlite3.connect(db_path) as conn:
        # Keep at least the most recent scan
        newest_scan_id = conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]

        old_scan_ids = [
            r[0] for r in conn.execute(
                "SELECT id FROM scans WHERE started_at < ?", (cutoff.isoformat(),)
            ).fetchall()
        ]

        # Never delete the newest scan
        if newest_scan_id is not None:
            old_scan_ids = [sid for sid in old_scan_ids if sid != newest_scan_id]

        if not old_scan_ids:
            logger.info("Retention cleanup: no scans to delete")
            return 0

        placeholders = ",".join("?" * len(old_scan_ids))

        # Delete in FK-safe order: alerts → changes → ports → devices → scans
        conn.execute(
            f"DELETE FROM alerts WHERE change_id IN "
            f"(SELECT id FROM changes WHERE scan_id IN ({placeholders}))",
            old_scan_ids,
        )
        conn.execute(f"DELETE FROM changes WHERE scan_id IN ({placeholders})", old_scan_ids)
        conn.execute(
            f"DELETE FROM ports WHERE device_id IN "
            f"(SELECT id FROM devices WHERE scan_id IN ({placeholders}))",
            old_scan_ids,
        )
        conn.execute(f"DELETE FROM devices WHERE scan_id IN ({placeholders})", old_scan_ids)
        conn.execute(f"DELETE FROM scans WHERE id IN ({placeholders})", old_scan_ids)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        logger.info(f"Retention cleanup: deleted {len(old_scan_ids)} old scans")
        return len(old_scan_ids)


def init_scheduler():
    """Initialize scheduler with saved configuration"""
    from app.config import get_config

    migrate_legacy_schedule()
    scheduler = get_scheduler()
    sync_scheduler_jobs()

    # Weekly retention cleanup — runs every Sunday at 3 AM
    config = get_config()
    scheduler.add_job(
        lambda: run_retention_cleanup(config.database.path, config.database.retention_days),
        trigger="cron",
        day_of_week="sun",
        hour=3,
        minute=0,
        id="retention_cleanup",
        replace_existing=True,
    )
    logger.info("Retention cleanup job scheduled (weekly, Sunday 03:00)")

    jobs = load_schedule_config()
    enabled_count = sum(1 for j in jobs if j.get("enabled", False))
    logger.info(f"Scheduler initialized with {enabled_count} active jobs")
