"""Change detection between network scans"""

import logging
from datetime import datetime
from typing import List, Dict, Set, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models import Scan, Device, Port, Change, DeviceHistory

logger = logging.getLogger(__name__)


class ChangeDetector:
    """Detects changes between network scans"""

    def __init__(self, db: Session):
        self.db = db

    def detect_changes(self, current_scan_id: int, previous_scan_id: int = None) -> List[Change]:
        """
        Detect changes between current scan and previous scan

        Args:
            current_scan_id: ID of the current scan
            previous_scan_id: ID of the previous scan (if None, uses the most recent)

        Returns:
            List of Change objects
        """
        current_scan = self.db.query(Scan).filter(Scan.id == current_scan_id).first()
        if not current_scan:
            logger.error(f"Current scan {current_scan_id} not found")
            return []

        # Get previous scan if not specified
        if previous_scan_id is None:
            previous_scan = (
                self.db.query(Scan)
                .filter(Scan.id < current_scan_id, Scan.status == "completed")
                .order_by(desc(Scan.id))
                .first()
            )
        else:
            previous_scan = self.db.query(Scan).filter(Scan.id == previous_scan_id).first()

        if not previous_scan:
            logger.info("No previous scan found for comparison")
            return []

        logger.info(
            f"Comparing scan {current_scan_id} with scan {previous_scan.id}"
        )

        changes = []

        # Detect device changes
        changes.extend(self._detect_device_changes(current_scan, previous_scan))

        # Detect port changes
        changes.extend(self._detect_port_changes(current_scan, previous_scan))

        # Update device history
        self._update_device_history(current_scan)

        logger.info(f"Detected {len(changes)} changes")

        return changes

    def _detect_device_changes(
        self, current_scan: Scan, previous_scan: Scan
    ) -> List[Change]:
        """Detect new and removed devices"""
        changes = []

        # Get device sets by MAC address (more reliable than IP)
        current_devices = {
            (d.mac_address or d.ip_address, d.ip_address): d
            for d in current_scan.devices
        }
        previous_devices = {
            (d.mac_address or d.ip_address, d.ip_address): d
            for d in previous_scan.devices
        }

        current_keys = set(current_devices.keys())
        previous_keys = set(previous_devices.keys())

        # New devices
        new_device_keys = current_keys - previous_keys
        for key in new_device_keys:
            device = current_devices[key]
            mac, ip = key

            change = Change(
                scan_id=current_scan.id,
                change_type="device_added",
                severity="warning",
                device_ip=ip,
                device_mac=mac if mac != ip else None,
                description=f"New device discovered: {ip} ({device.hostname or 'unknown'})",
                detected_at=datetime.utcnow(),
            )
            self.db.add(change)
            changes.append(change)

        # Removed devices
        removed_device_keys = previous_keys - current_keys
        for key in removed_device_keys:
            device = previous_devices[key]
            mac, ip = key

            change = Change(
                scan_id=current_scan.id,
                change_type="device_removed",
                severity="info",
                device_ip=ip,
                device_mac=mac if mac != ip else None,
                description=f"Device no longer detected: {ip} ({device.hostname or 'unknown'})",
                detected_at=datetime.utcnow(),
            )
            self.db.add(change)
            changes.append(change)

        # Check for IP address changes (same MAC, different IP)
        current_by_mac = {
            d.mac_address: d for d in current_scan.devices if d.mac_address
        }
        previous_by_mac = {
            d.mac_address: d for d in previous_scan.devices if d.mac_address
        }

        for mac, current_device in current_by_mac.items():
            if mac in previous_by_mac:
                previous_device = previous_by_mac[mac]
                if current_device.ip_address != previous_device.ip_address:
                    change = Change(
                        scan_id=current_scan.id,
                        change_type="device_ip_changed",
                        severity="info",
                        device_ip=current_device.ip_address,
                        device_mac=mac,
                        old_value=previous_device.ip_address,
                        new_value=current_device.ip_address,
                        description=f"Device IP changed: {previous_device.ip_address} -> {current_device.ip_address}",
                        detected_at=datetime.utcnow(),
                    )
                    self.db.add(change)
                    changes.append(change)

        self.db.commit()
        return changes

    def _detect_port_changes(
        self, current_scan: Scan, previous_scan: Scan
    ) -> List[Change]:
        """Detect opened and closed ports"""
        changes = []

        # Build device mapping by MAC address
        current_devices_by_mac = {
            d.mac_address or d.ip_address: d for d in current_scan.devices
        }
        previous_devices_by_mac = {
            d.mac_address or d.ip_address: d for d in previous_scan.devices
        }

        # Compare ports for matching devices
        for mac, current_device in current_devices_by_mac.items():
            if mac not in previous_devices_by_mac:
                continue

            previous_device = previous_devices_by_mac[mac]

            # Get port sets
            current_ports = {
                (p.port_number, p.protocol): p for p in current_device.ports
            }
            previous_ports = {
                (p.port_number, p.protocol): p for p in previous_device.ports
            }

            current_port_keys = set(current_ports.keys())
            previous_port_keys = set(previous_ports.keys())

            # New open ports
            new_ports = current_port_keys - previous_port_keys
            for port_key in new_ports:
                port_num, protocol = port_key
                port = current_ports[port_key]

                severity = self._assess_port_severity(port_num, port.service_name)

                change = Change(
                    scan_id=current_scan.id,
                    change_type="port_opened",
                    severity=severity,
                    device_ip=current_device.ip_address,
                    device_mac=current_device.mac_address,
                    port_number=port_num,
                    protocol=protocol,
                    new_value=port.service_name or "unknown",
                    description=f"Port opened on {current_device.ip_address}: {port_num}/{protocol} ({port.service_name or 'unknown'})",
                    detected_at=datetime.utcnow(),
                )
                self.db.add(change)
                changes.append(change)

            # Closed ports
            closed_ports = previous_port_keys - current_port_keys
            for port_key in closed_ports:
                port_num, protocol = port_key
                port = previous_ports[port_key]

                change = Change(
                    scan_id=current_scan.id,
                    change_type="port_closed",
                    severity="info",
                    device_ip=current_device.ip_address,
                    device_mac=current_device.mac_address,
                    port_number=port_num,
                    protocol=protocol,
                    old_value=port.service_name or "unknown",
                    description=f"Port closed on {current_device.ip_address}: {port_num}/{protocol} ({port.service_name or 'unknown'})",
                    detected_at=datetime.utcnow(),
                )
                self.db.add(change)
                changes.append(change)

            # Service version changes
            for port_key in current_port_keys & previous_port_keys:
                current_port = current_ports[port_key]
                previous_port = previous_ports[port_key]

                if current_port.service_version != previous_port.service_version:
                    port_num, protocol = port_key

                    change = Change(
                        scan_id=current_scan.id,
                        change_type="service_changed",
                        severity="info",
                        device_ip=current_device.ip_address,
                        device_mac=current_device.mac_address,
                        port_number=port_num,
                        protocol=protocol,
                        old_value=previous_port.service_version or "unknown",
                        new_value=current_port.service_version or "unknown",
                        description=f"Service version changed on {current_device.ip_address}:{port_num} - {previous_port.service_version} -> {current_port.service_version}",
                        detected_at=datetime.utcnow(),
                    )
                    self.db.add(change)
                    changes.append(change)

        self.db.commit()
        return changes

    def _assess_port_severity(self, port_number: int, service_name: str = None) -> str:
        """
        Assess severity of a newly opened port

        Returns: "info", "warning", or "critical"
        """
        # Common suspicious ports
        suspicious_ports = {
            21: "ftp",  # FTP
            23: "telnet",  # Telnet
            135: "msrpc",  # MS RPC
            139: "netbios",  # NetBIOS
            445: "smb",  # SMB
            1433: "mssql",  # MS SQL
            3306: "mysql",  # MySQL
            3389: "rdp",  # RDP
            5900: "vnc",  # VNC
            6379: "redis",  # Redis
        }

        # Common malware ports
        malware_ports = {
            31337: "Back Orifice",
            12345: "NetBus",
            54321: "Back Orifice 2000",
            1337: "Common hacker port",
        }

        if port_number in malware_ports:
            return "critical"

        if port_number in suspicious_ports:
            return "warning"

        return "info"

    def _update_device_history(self, scan: Scan) -> None:
        """Update device history for persistent tracking"""
        for device in scan.devices:
            if not device.mac_address:
                continue

            history = (
                self.db.query(DeviceHistory)
                .filter(DeviceHistory.mac_address == device.mac_address)
                .first()
            )

            if history:
                # Update existing history
                history.last_ip = device.ip_address
                history.last_hostname = device.hostname
                history.last_seen = datetime.utcnow()
                history.times_seen += 1
            else:
                # Create new history
                history = DeviceHistory(
                    mac_address=device.mac_address,
                    last_ip=device.ip_address,
                    last_hostname=device.hostname,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    times_seen=1,
                )
                self.db.add(history)

        self.db.commit()
