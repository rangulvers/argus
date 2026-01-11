#!/usr/bin/env python3
"""
Development Reset Script

Resets the Argus database for development:
- Clears all scans, devices, ports, changes, alerts, and history
- Creates ADMIN user with password ADMIN1234
- Sets scan subnet to 10.10.10.0/24

Usage:
    python scripts/dev_reset.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal, init_db, engine, Base
from app.models import Scan, Device, Port, Change, Alert, DeviceHistory, User, APIKey, AuditLog
from app.auth import hash_password
from app.config import get_config, save_config, reload_config


def reset_database():
    """Clear all data from the database"""
    print("Resetting database...")

    db = SessionLocal()
    try:
        # Delete in order respecting foreign keys
        deleted_counts = {}

        # Alerts depend on Changes
        count = db.query(Alert).delete()
        deleted_counts['alerts'] = count

        # Changes depend on Scans
        count = db.query(Change).delete()
        deleted_counts['changes'] = count

        # Ports depend on Devices
        count = db.query(Port).delete()
        deleted_counts['ports'] = count

        # Devices depend on Scans
        count = db.query(Device).delete()
        deleted_counts['devices'] = count

        # Scans (no dependencies)
        count = db.query(Scan).delete()
        deleted_counts['scans'] = count

        # DeviceHistory (standalone)
        count = db.query(DeviceHistory).delete()
        deleted_counts['device_history'] = count

        # APIKeys depend on Users
        count = db.query(APIKey).delete()
        deleted_counts['api_keys'] = count

        # AuditLogs reference Users (but nullable)
        count = db.query(AuditLog).delete()
        deleted_counts['audit_logs'] = count

        # Users (standalone)
        count = db.query(User).delete()
        deleted_counts['users'] = count

        db.commit()

        print("  Deleted records:")
        for table, count in deleted_counts.items():
            if count > 0:
                print(f"    - {table}: {count}")

        if all(c == 0 for c in deleted_counts.values()):
            print("    (database was already empty)")

    finally:
        db.close()


def create_admin_user():
    """Create ADMIN user with password ADMIN1234"""
    print("\nCreating ADMIN user...")

    db = SessionLocal()
    try:
        # Check if user already exists
        existing = db.query(User).filter(User.username == "ADMIN").first()
        if existing:
            print("  ADMIN user already exists, updating password...")
            existing.password_hash = hash_password("ADMIN1234")
        else:
            admin = User(
                username="ADMIN",
                password_hash=hash_password("ADMIN1234")
            )
            db.add(admin)
            print("  Created ADMIN user")

        db.commit()
        print("  Username: ADMIN")
        print("  Password: ADMIN1234")

    finally:
        db.close()


def set_scan_subnet():
    """Set the scan subnet to 10.10.10.0/24"""
    print("\nUpdating scan configuration...")

    config = get_config()
    old_subnet = config.network.subnet

    # Update subnet
    config.network.subnet = "10.10.10.0/24"

    # Save to config.yaml
    save_config(config)

    # Reload to verify
    reload_config()

    print(f"  Subnet changed: {old_subnet} -> 10.10.10.0/24")


def main():
    print("=" * 60)
    print("Argus Development Reset Script")
    print("=" * 60)

    # Ensure data directory exists
    os.makedirs("./data", exist_ok=True)

    # Initialize database (creates tables if they don't exist)
    print("\nInitializing database schema...")
    init_db()
    print("  Database schema ready")

    # Reset data
    reset_database()

    # Create admin user
    create_admin_user()

    # Set scan subnet
    set_scan_subnet()

    print("\n" + "=" * 60)
    print("Development environment reset complete!")
    print("=" * 60)
    print("\nYou can now:")
    print("  1. Start the server: uvicorn app.main:app --reload")
    print("  2. Login with ADMIN / ADMIN1234")
    print("  3. Scan subnet 10.10.10.0/24")
    print()


if __name__ == "__main__":
    main()
