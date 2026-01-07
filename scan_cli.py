#!/usr/bin/env python3
"""CLI tool for running network scans"""

import argparse
import logging
import sys
from app.database import SessionLocal, init_db
from app.scanner import NetworkScanner
from app.utils.change_detector import ChangeDetector
from app.config import get_config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("argus.log"),
    ],
)

logger = logging.getLogger(__name__)


def run_scan(args):
    """Run a network scan"""
    logger.info("Starting network scan")

    # Initialize database
    init_db()

    # Get database session
    db = SessionLocal()

    try:
        # Load config
        config = get_config()

        # Get scan parameters
        subnet = args.subnet or config.network.subnet
        scan_profile = args.profile or config.network.scan_profile
        port_range = args.ports or config.scanning.port_range

        logger.info(f"Scanning {subnet} with profile '{scan_profile}' and ports '{port_range}'")

        # Create scanner and perform scan
        scanner = NetworkScanner(db)
        scan = scanner.perform_scan(
            subnet=subnet,
            scan_profile=scan_profile,
            port_range=port_range,
            enable_os_detection=config.scanning.enable_os_detection,
            enable_service_detection=config.scanning.enable_service_detection,
        )

        logger.info(f"Scan completed: ID={scan.id}, Status={scan.status}, Devices={scan.devices_found}")

        # Detect changes if requested
        if args.detect_changes and scan.status == "completed":
            logger.info("Detecting changes from previous scan...")
            detector = ChangeDetector(db)
            changes = detector.detect_changes(scan.id)

            if changes:
                logger.info(f"Detected {len(changes)} changes:")
                for change in changes:
                    logger.info(f"  - [{change.severity.upper()}] {change.description}")
            else:
                logger.info("No changes detected")

        # Print summary
        print("\n" + "=" * 60)
        print(f"Scan ID: {scan.id}")
        print(f"Status: {scan.status}")
        print(f"Subnet: {scan.subnet}")
        print(f"Started: {scan.started_at}")
        print(f"Completed: {scan.completed_at}")
        print(f"Devices Found: {scan.devices_found}")

        if scan.status == "completed" and scan.devices:
            print("\nDevices:")
            for device in scan.devices:
                print(f"\n  {device.ip_address}")
                if device.mac_address:
                    print(f"    MAC: {device.mac_address}")
                if device.hostname:
                    print(f"    Hostname: {device.hostname}")
                if device.vendor:
                    print(f"    Vendor: {device.vendor}")
                if device.os_name:
                    print(f"    OS: {device.os_name} ({device.os_accuracy}% accuracy)")

                if device.ports:
                    print(f"    Open Ports:")
                    for port in device.ports:
                        service_info = f"{port.service_name}" if port.service_name else "unknown"
                        if port.service_version:
                            service_info += f" ({port.service_version})"
                        print(f"      - {port.port_number}/{port.protocol}: {service_info}")

        print("=" * 60 + "\n")

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        sys.exit(1)
    finally:
        db.close()


def list_scans(args):
    """List recent scans"""
    db = SessionLocal()

    try:
        from app.models import Scan
        from sqlalchemy import desc

        scans = db.query(Scan).order_by(desc(Scan.started_at)).limit(args.limit).all()

        if not scans:
            print("No scans found")
            return

        print("\nRecent Scans:")
        print("=" * 80)
        print(f"{'ID':<6} {'Status':<12} {'Subnet':<20} {'Devices':<8} {'Started':<20}")
        print("=" * 80)

        for scan in scans:
            print(
                f"{scan.id:<6} {scan.status:<12} {scan.subnet:<20} "
                f"{scan.devices_found:<8} {scan.started_at.strftime('%Y-%m-%d %H:%M:%S')}"
            )

        print("=" * 80 + "\n")

    finally:
        db.close()


def list_devices(args):
    """List devices from a scan"""
    db = SessionLocal()

    try:
        from app.models import Scan, Device
        from sqlalchemy import desc

        if args.scan_id:
            scan = db.query(Scan).filter(Scan.id == args.scan_id).first()
        else:
            # Get most recent completed scan
            scan = (
                db.query(Scan)
                .filter(Scan.status == "completed")
                .order_by(desc(Scan.id))
                .first()
            )

        if not scan:
            print("No scan found")
            return

        print(f"\nDevices from Scan #{scan.id} ({scan.started_at}):")
        print("=" * 100)
        print(f"{'IP Address':<16} {'MAC Address':<18} {'Hostname':<20} {'Vendor':<30} {'Ports':<8}")
        print("=" * 100)

        for device in scan.devices:
            mac = device.mac_address or "N/A"
            hostname = device.hostname or "N/A"
            vendor = device.vendor or "N/A"
            port_count = len(device.ports)

            print(f"{device.ip_address:<16} {mac:<18} {hostname:<20} {vendor:<30} {port_count:<8}")

        print("=" * 100 + "\n")

    finally:
        db.close()


def list_changes(args):
    """List recent changes"""
    db = SessionLocal()

    try:
        from app.models import Change
        from sqlalchemy import desc

        query = db.query(Change).order_by(desc(Change.detected_at))

        if args.scan_id:
            query = query.filter(Change.scan_id == args.scan_id)

        changes = query.limit(args.limit).all()

        if not changes:
            print("No changes found")
            return

        print("\nRecent Changes:")
        print("=" * 120)
        print(f"{'ID':<6} {'Type':<20} {'Severity':<10} {'Device':<20} {'Description':<60}")
        print("=" * 120)

        for change in changes:
            device = change.device_ip or "N/A"
            desc_text = change.description[:57] + "..." if len(change.description) > 60 else change.description

            print(
                f"{change.id:<6} {change.change_type:<20} {change.severity:<10} "
                f"{device:<20} {desc_text:<60}"
            )

        print("=" * 120 + "\n")

    finally:
        db.close()


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Argus - Network Security Scanner CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run a network scan")
    scan_parser.add_argument("--subnet", "-s", help="Network subnet to scan (e.g., 192.168.1.0/24)")
    scan_parser.add_argument("--profile", "-p", choices=["quick", "normal", "intensive"], help="Scan profile")
    scan_parser.add_argument("--ports", help="Port range (e.g., 1-1000, common, all)")
    scan_parser.add_argument("--detect-changes", "-c", action="store_true", help="Detect changes from previous scan")
    scan_parser.set_defaults(func=run_scan)

    # List scans command
    list_scans_parser = subparsers.add_parser("list-scans", help="List recent scans")
    list_scans_parser.add_argument("--limit", "-l", type=int, default=10, help="Number of scans to show")
    list_scans_parser.set_defaults(func=list_scans)

    # List devices command
    list_devices_parser = subparsers.add_parser("list-devices", help="List devices from a scan")
    list_devices_parser.add_argument("--scan-id", type=int, help="Scan ID (default: most recent)")
    list_devices_parser.set_defaults(func=list_devices)

    # List changes command
    list_changes_parser = subparsers.add_parser("list-changes", help="List recent changes")
    list_changes_parser.add_argument("--scan-id", type=int, help="Filter by scan ID")
    list_changes_parser.add_argument("--limit", "-l", type=int, default=20, help="Number of changes to show")
    list_changes_parser.set_defaults(func=list_changes)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
