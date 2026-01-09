"""Network scanner using nmap"""

import nmap
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models import Scan, Device, Port, DeviceHistory
from app.utils.threat_detector import ThreatDetector
from app.utils.mac_vendor import get_vendor_lookup

logger = logging.getLogger(__name__)


class NetworkScanner:
    """Network scanner using nmap"""

    def __init__(self, db: Session):
        self.db = db
        self.nm = nmap.PortScanner()
        self.threat_detector = ThreatDetector()
        self.mac_vendor = get_vendor_lookup()

    def perform_scan(
        self,
        subnet: str,
        scan_profile: str = "normal",
        port_range: str = "1-1000",
        enable_os_detection: bool = True,
        enable_service_detection: bool = True,
        scan_type: str = "network",
    ) -> Scan:
        """
        Perform a network scan

        Args:
            subnet: Network subnet to scan (e.g., "192.168.1.0/24")
            scan_profile: Scan intensity (quick, normal, intensive)
            port_range: Port range to scan (e.g., "1-1000", "common", "all")
            enable_os_detection: Enable OS fingerprinting
            enable_service_detection: Enable service/version detection
            scan_type: Type of scan ("network" for full subnet, "device" for single device)

        Returns:
            Scan object with results
        """
        logger.info(f"Starting scan of {subnet} with profile {scan_profile}")

        # Estimate scan time
        time_estimates = {
            "quick": "30 seconds - 2 minutes",
            "normal": "5-15 minutes",
            "intensive": "15-45 minutes"
        }
        estimated_time = time_estimates.get(scan_profile, "5-15 minutes")

        # Print progress info to console
        print(f"\n{'='*60}")
        print(f"Starting network scan...")
        print(f"  Subnet: {subnet}")
        print(f"  Profile: {scan_profile}")
        if scan_profile != "quick":
            print(f"  Ports: {port_range}")
        print(f"  Estimated time: {estimated_time}")
        print(f"{'='*60}")
        print(f"\nPlease wait while nmap scans your network...")
        print(f"(The scan is running - no output means it's still working)\n")

        # Create scan record
        scan = Scan(
            started_at=datetime.utcnow(),
            status="running",
            scan_type=scan_type,
            scan_profile=scan_profile,
            subnet=subnet,
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)

        try:
            # Build nmap arguments based on profile and options
            nmap_args = self._build_nmap_args(
                scan_profile, port_range, enable_os_detection, enable_service_detection
            )

            logger.info(f"Nmap arguments: {nmap_args}")
            print(f"Running nmap with arguments: {nmap_args}")
            print(f"Scanning... (this is the slow part)\n")

            # Perform the scan
            self.nm.scan(hosts=subnet, arguments=nmap_args)

            print(f"\nScan complete! Processing results...")

            # Process results
            devices_found = 0
            all_hosts = self.nm.all_hosts()
            total_hosts = len(all_hosts)

            for i, host in enumerate(all_hosts, 1):
                if self.nm[host].state() == "up":
                    print(f"  Processing host {i}/{total_hosts}: {host}")
                    device = self._process_host(scan.id, host, scan_profile)
                    if device:
                        devices_found += 1

            # Update scan status
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            scan.devices_found = devices_found

            # Count threats
            devices_with_threats = self.db.query(Device).filter(
                Device.scan_id == scan.id,
                Device.risk_level.in_(["medium", "high", "critical"])
            ).count()
            critical_count = self.db.query(Device).filter(
                Device.scan_id == scan.id,
                Device.risk_level == "critical"
            ).count()
            high_count = self.db.query(Device).filter(
                Device.scan_id == scan.id,
                Device.risk_level == "high"
            ).count()

            print(f"\n{'='*60}")
            print(f"Scan finished!")
            print(f"  Devices found: {devices_found}")
            print(f"  Duration: {(scan.completed_at - scan.started_at).seconds} seconds")
            if devices_with_threats > 0:
                print(f"\n  ⚠️  SECURITY SUMMARY:")
                print(f"  Devices with threats: {devices_with_threats}")
                if critical_count:
                    print(f"    - Critical risk: {critical_count}")
                if high_count:
                    print(f"    - High risk: {high_count}")
                print(f"\n  View details at http://localhost:8080/devices")
            else:
                print(f"\n  ✓ No significant threats detected")
            print(f"{'='*60}\n")

            logger.info(f"Scan completed. Found {devices_found} devices")

        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            scan.status = "failed"
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()

        self.db.commit()
        self.db.refresh(scan)

        return scan

    def _build_nmap_args(
        self,
        scan_profile: str,
        port_range: str,
        enable_os_detection: bool,
        enable_service_detection: bool,
    ) -> str:
        """Build nmap command arguments based on options"""
        args = []

        # Scan profile timing
        if scan_profile == "quick":
            # Quick profile: ping scan only (host discovery, no port scan)
            args.append("-sn")  # Ping scan only
            args.append("-T4")  # Aggressive timing
        elif scan_profile == "intensive":
            # Intensive: full scan with OS detection, scripts, etc.
            args.append("-T3")  # Normal timing
            args.append("-A")  # Aggressive scan (OS, version, scripts, traceroute)
            # Port range for intensive scan
            if port_range == "common":
                args.append("-F")
            elif port_range == "all":
                args.append("-p-")
            else:
                args.append(f"-p {port_range}")
        else:  # normal
            args.append("-T3")
            # Port range
            if port_range == "common":
                args.append("-F")
            elif port_range == "all":
                args.append("-p-")
            else:
                args.append(f"-p {port_range}")
            if enable_service_detection:
                args.append("-sV")  # Version detection
            if enable_os_detection:
                args.append("-O")  # OS detection

        return " ".join(args)

    def _get_previous_device(self, mac_address: Optional[str], ip_address: str) -> Optional[Device]:
        """Find the most recent device record for this MAC or IP"""
        if mac_address:
            # First try to find by MAC address (most reliable)
            prev_device = (
                self.db.query(Device)
                .join(Scan)
                .filter(Device.mac_address == mac_address, Scan.status == "completed")
                .order_by(desc(Scan.started_at))
                .first()
            )
            if prev_device:
                return prev_device

        # Fallback to IP address
        prev_device = (
            self.db.query(Device)
            .join(Scan)
            .filter(Device.ip_address == ip_address, Scan.status == "completed")
            .order_by(desc(Scan.started_at))
            .first()
        )
        return prev_device

    def _copy_ports_from_device(self, source_device: Device, target_device_id: int) -> List[Tuple]:
        """Copy ports from a previous device to the new device"""
        ports_list = []
        for port in source_device.ports:
            new_port = Port(
                device_id=target_device_id,
                port_number=port.port_number,
                protocol=port.protocol,
                state=port.state,
                service_name=port.service_name,
                service_product=port.service_product,
                service_version=port.service_version,
                service_extra_info=port.service_extra_info,
            )
            self.db.add(new_port)
            if port.state == "open":
                ports_list.append((port.port_number, port.protocol, port.service_name or ""))
        self.db.commit()
        return ports_list

    def _update_device_history(self, device: Device) -> None:
        """Update or create DeviceHistory record"""
        if not device.mac_address:
            return

        history = self.db.query(DeviceHistory).filter(
            DeviceHistory.mac_address == device.mac_address
        ).first()

        if history:
            # Update existing record
            history.last_ip = device.ip_address
            history.last_hostname = device.hostname
            history.last_seen = datetime.utcnow()
            history.times_seen += 1
        else:
            # Create new record
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

    def _process_host(self, scan_id: int, host: str, scan_profile: str) -> Optional[Device]:
        """Process a single host and create device record, merging with previous data"""
        try:
            host_data = self.nm[host]

            # Extract basic info from current scan
            hostname = host_data.hostname() if host_data.hostname() else None
            mac_address = None
            vendor = None
            device_type = None

            # Get MAC address if available
            if "mac" in host_data["addresses"]:
                mac_address = host_data["addresses"]["mac"]

            # Get vendor from Wireshark manuf database (more comprehensive)
            if mac_address:
                vendor_info = self.mac_vendor.lookup(mac_address)
                if vendor_info:
                    vendor = vendor_info.get('full_name')
                    device_type = vendor_info.get('device_type')

            # Fallback to nmap vendor if Wireshark lookup failed
            if not vendor and "vendor" in host_data and host_data["vendor"]:
                vendor = list(host_data["vendor"].values())[0] if host_data["vendor"] else None

            # Get OS detection info
            os_name = None
            os_accuracy = None
            if "osmatch" in host_data and host_data["osmatch"]:
                os_match = host_data["osmatch"][0]
                os_name = os_match.get("name")
                os_accuracy = int(os_match.get("accuracy", 0))

            # Look up previous device data to merge
            prev_device = self._get_previous_device(mac_address, host)
            first_seen = datetime.utcnow()

            if prev_device:
                # Merge with previous data - keep previous values if current scan didn't detect them
                if not hostname and prev_device.hostname:
                    hostname = prev_device.hostname
                if not vendor and prev_device.vendor:
                    vendor = prev_device.vendor
                if not device_type and prev_device.device_type:
                    device_type = prev_device.device_type
                if not os_name and prev_device.os_name:
                    os_name = prev_device.os_name
                    os_accuracy = prev_device.os_accuracy
                # Preserve first_seen from the earliest record
                first_seen = prev_device.first_seen
                # Carry forward user-defined fields
                label = prev_device.label
                is_trusted = prev_device.is_trusted
                notes = prev_device.notes
                zone = prev_device.zone
            else:
                label = None
                is_trusted = False
                notes = None
                zone = None

            # Create device record
            device = Device(
                scan_id=scan_id,
                ip_address=host,
                mac_address=mac_address,
                hostname=hostname,
                vendor=vendor,
                device_type=device_type,
                os_name=os_name,
                os_accuracy=os_accuracy,
                status="up",
                first_seen=first_seen,
                last_seen=datetime.utcnow(),
                label=label,
                is_trusted=is_trusted,
                notes=notes,
                zone=zone,
            )

            self.db.add(device)
            self.db.commit()
            self.db.refresh(device)

            # Process ports - behavior depends on scan profile
            ports_list = []
            is_quick_scan = (scan_profile == "quick")

            if is_quick_scan and prev_device and prev_device.ports:
                # Quick scan: carry forward ports from previous scan
                print(f"    (Carrying forward {len(prev_device.ports)} ports from previous scan)")
                ports_list = self._copy_ports_from_device(prev_device, device.id)
                # Also carry forward threat assessment
                device.risk_level = prev_device.risk_level
                device.risk_score = prev_device.risk_score
                device.threat_summary = prev_device.threat_summary
                device.threat_details = prev_device.threat_details
                self.db.commit()
            else:
                # Normal/intensive scan: process new port data
                if "tcp" in host_data:
                    for port_num, port_data in host_data["tcp"].items():
                        self._process_port(device.id, port_num, "tcp", port_data)
                        if port_data.get("state") == "open":
                            ports_list.append((
                                port_num,
                                "tcp",
                                port_data.get("name", ""),
                                port_data.get("product", ""),
                                port_data.get("version", "")
                            ))

                if "udp" in host_data:
                    for port_num, port_data in host_data["udp"].items():
                        self._process_port(device.id, port_num, "udp", port_data)
                        if port_data.get("state") == "open":
                            ports_list.append((
                                port_num,
                                "udp",
                                port_data.get("name", ""),
                                port_data.get("product", ""),
                                port_data.get("version", "")
                            ))

                # Perform threat assessment on new data
                if ports_list:
                    assessment = self.threat_detector.assess_device(ports_list)
                    device.risk_level = assessment.risk_level.value
                    device.risk_score = assessment.risk_score
                    device.threat_summary = assessment.summary
                    device.threat_details = {
                        "threats": [
                            {
                                "port": t.port,
                                "protocol": t.protocol,
                                "risk_level": t.risk_level.value,
                                "service_name": t.service_name,
                                "description": t.threat_description,
                                "recommendation": t.recommendation,
                                "cves": [
                                    {
                                        "id": cve.cve_id,
                                        "description": cve.description,
                                        "severity": cve.severity,
                                        "cvss_score": cve.cvss_score
                                    }
                                    for cve in (t.cves or [])
                                ]
                            }
                            for t in assessment.threats
                        ],
                        "cves": [
                            {
                                "id": cve.cve_id,
                                "description": cve.description,
                                "severity": cve.severity,
                                "cvss_score": cve.cvss_score,
                                "remediation": cve.remediation,
                                "references": cve.references
                            }
                            for cve in assessment.cves
                        ],
                        "top_recommendation": assessment.top_recommendation
                    }
                    self.db.commit()

                    # Print threat warning if risky
                    if assessment.risk_level.value in ("high", "critical"):
                        print(f"    ⚠️  THREAT DETECTED: {assessment.summary}")

            # Update device history
            self._update_device_history(device)

            logger.info(f"Processed device: {host} ({mac_address})")

            return device

        except Exception as e:
            logger.error(f"Error processing host {host}: {str(e)}")
            return None

    def _process_port(
        self, device_id: int, port_number: int, protocol: str, port_data: Dict
    ) -> None:
        """Process a single port and create port record"""
        try:
            state = port_data.get("state", "unknown")

            # Only record open ports
            if state != "open":
                return

            service_name = port_data.get("name")
            service_product = port_data.get("product")
            service_version = port_data.get("version")
            service_extra_info = port_data.get("extrainfo")

            port = Port(
                device_id=device_id,
                port_number=port_number,
                protocol=protocol,
                state=state,
                service_name=service_name,
                service_product=service_product,
                service_version=service_version,
                service_extra_info=service_extra_info,
            )

            self.db.add(port)
            self.db.commit()

            logger.debug(
                f"Added port: {port_number}/{protocol} - {service_name} ({state})"
            )

        except Exception as e:
            logger.error(f"Error processing port {port_number}: {str(e)}")

    def quick_ping_scan(self, subnet: str) -> List[str]:
        """
        Perform a quick ping scan to find active hosts

        Args:
            subnet: Network subnet to scan

        Returns:
            List of active IP addresses
        """
        logger.info(f"Performing quick ping scan of {subnet}")

        try:
            self.nm.scan(hosts=subnet, arguments="-sn -T4")
            active_hosts = [host for host in self.nm.all_hosts() if self.nm[host].state() == "up"]
            logger.info(f"Found {len(active_hosts)} active hosts")
            return active_hosts
        except Exception as e:
            logger.error(f"Ping scan failed: {str(e)}")
            return []
