"""Threat detection for network devices based on open ports"""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum

from app.utils.cve_database import (
    find_cves_strict,
    CVEEntry,
    CVEMatchResult,
    severity_to_score,
    EntryType
)


class RiskLevel(Enum):
    """Risk level classifications"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PortThreat:
    """Information about a potentially risky port"""
    port: int
    protocol: str
    risk_level: RiskLevel
    service_name: str
    threat_description: str
    recommendation: str
    cve_references: List[str] = None
    cves: List[CVEMatchResult] = None  # Confirmed CVEs with match info
    warnings: List[CVEEntry] = None  # Protocol warnings (separate from CVEs)

    def __post_init__(self):
        if self.cve_references is None:
            self.cve_references = []
        if self.cves is None:
            self.cves = []
        if self.warnings is None:
            self.warnings = []


# Database of known risky ports
# This covers common security concerns for home networks
THREAT_DATABASE: Dict[int, PortThreat] = {
    # Critical - Should never be open on home network
    23: PortThreat(
        port=23,
        protocol="tcp",
        risk_level=RiskLevel.CRITICAL,
        service_name="Telnet",
        threat_description="Telnet transmits all data including passwords in plain text. Extremely insecure.",
        recommendation="Disable Telnet immediately and use SSH instead. If this is a router or IoT device, check for firmware updates or replace the device."
    ),
    512: PortThreat(
        port=512,
        protocol="tcp",
        risk_level=RiskLevel.CRITICAL,
        service_name="rexec",
        threat_description="Remote execution service with weak authentication. Common attack vector.",
        recommendation="Disable this service immediately. It should never be enabled on modern systems."
    ),
    513: PortThreat(
        port=513,
        protocol="tcp",
        risk_level=RiskLevel.CRITICAL,
        service_name="rlogin",
        threat_description="Remote login with weak authentication. Transmits data in plain text.",
        recommendation="Disable this service and use SSH instead."
    ),
    514: PortThreat(
        port=514,
        protocol="tcp",
        risk_level=RiskLevel.CRITICAL,
        service_name="rsh",
        threat_description="Remote shell with minimal authentication. Major security risk.",
        recommendation="Disable this service immediately and use SSH instead."
    ),

    # High Risk - Common attack targets
    21: PortThreat(
        port=21,
        protocol="tcp",
        risk_level=RiskLevel.HIGH,
        service_name="FTP",
        threat_description="FTP transmits credentials in plain text. Often misconfigured with anonymous access.",
        recommendation="Use SFTP or FTPS instead. If FTP is required, ensure strong passwords and disable anonymous access."
    ),
    25: PortThreat(
        port=25,
        protocol="tcp",
        risk_level=RiskLevel.HIGH,
        service_name="SMTP",
        threat_description="Mail server exposed. Can be abused for spam relay if misconfigured.",
        recommendation="Unless running a mail server, this port should be closed. Ensure proper authentication if needed."
    ),
    135: PortThreat(
        port=135,
        protocol="tcp",
        risk_level=RiskLevel.HIGH,
        service_name="MS-RPC",
        threat_description="Windows RPC endpoint. Frequently targeted by malware and worms (e.g., Blaster worm).",
        recommendation="Block from external access. Ensure Windows Firewall is enabled."
    ),
    137: PortThreat(
        port=137,
        protocol="udp",
        risk_level=RiskLevel.HIGH,
        service_name="NetBIOS-NS",
        threat_description="NetBIOS Name Service. Can leak system information and is targeted by attackers.",
        recommendation="Disable NetBIOS over TCP/IP if not needed. Block from external access."
    ),
    138: PortThreat(
        port=138,
        protocol="udp",
        risk_level=RiskLevel.HIGH,
        service_name="NetBIOS-DGM",
        threat_description="NetBIOS Datagram Service. Can be exploited for information gathering.",
        recommendation="Disable NetBIOS over TCP/IP if not needed."
    ),
    139: PortThreat(
        port=139,
        protocol="tcp",
        risk_level=RiskLevel.HIGH,
        service_name="NetBIOS-SSN",
        threat_description="NetBIOS Session Service. Used by older Windows file sharing, vulnerable to attacks.",
        recommendation="Use SMB over port 445 instead. Disable NetBIOS if not needed."
    ),
    445: PortThreat(
        port=445,
        protocol="tcp",
        risk_level=RiskLevel.HIGH,
        service_name="SMB",
        threat_description="Windows file sharing. Target of ransomware (WannaCry, NotPetya) and other attacks.",
        recommendation="Ensure SMBv1 is disabled. Keep Windows updated. Block from external/internet access.",
        cve_references=["CVE-2017-0144", "CVE-2020-0796"]
    ),
    1433: PortThreat(
        port=1433,
        protocol="tcp",
        risk_level=RiskLevel.HIGH,
        service_name="MS-SQL",
        threat_description="Microsoft SQL Server. Database servers should never be directly exposed.",
        recommendation="Block from external access. Use VPN or SSH tunnel for remote access."
    ),
    1434: PortThreat(
        port=1434,
        protocol="udp",
        risk_level=RiskLevel.HIGH,
        service_name="MS-SQL Browser",
        threat_description="SQL Server Browser service. Can be used to discover SQL instances.",
        recommendation="Disable if not needed. Block from external access."
    ),
    3306: PortThreat(
        port=3306,
        protocol="tcp",
        risk_level=RiskLevel.HIGH,
        service_name="MySQL",
        threat_description="MySQL database. Should not be exposed to the network without strong authentication.",
        recommendation="Bind to localhost only or use firewall rules. Use strong passwords."
    ),
    3389: PortThreat(
        port=3389,
        protocol="tcp",
        risk_level=RiskLevel.HIGH,
        service_name="RDP",
        threat_description="Remote Desktop Protocol. Major target for brute force attacks and ransomware.",
        recommendation="Disable if not needed. Use VPN for remote access. Enable Network Level Authentication.",
        cve_references=["CVE-2019-0708"]
    ),
    5900: PortThreat(
        port=5900,
        protocol="tcp",
        risk_level=RiskLevel.HIGH,
        service_name="VNC",
        threat_description="Virtual Network Computing. Often has weak authentication or none at all.",
        recommendation="Use SSH tunneling for VNC access. Ensure strong password is set."
    ),
    5901: PortThreat(
        port=5901,
        protocol="tcp",
        risk_level=RiskLevel.HIGH,
        service_name="VNC-1",
        threat_description="VNC display :1. Same risks as port 5900.",
        recommendation="Use SSH tunneling for VNC access. Ensure strong password is set."
    ),
    6379: PortThreat(
        port=6379,
        protocol="tcp",
        risk_level=RiskLevel.HIGH,
        service_name="Redis",
        threat_description="Redis database. Often deployed without authentication. Can lead to remote code execution.",
        recommendation="Bind to localhost only. Enable authentication with strong password."
    ),
    27017: PortThreat(
        port=27017,
        protocol="tcp",
        risk_level=RiskLevel.HIGH,
        service_name="MongoDB",
        threat_description="MongoDB database. Historically deployed without authentication by default.",
        recommendation="Enable authentication. Bind to localhost or use firewall rules."
    ),

    # Medium Risk - Should be monitored
    22: PortThreat(
        port=22,
        protocol="tcp",
        risk_level=RiskLevel.MEDIUM,
        service_name="SSH",
        threat_description="Secure Shell. Generally safe but targeted by brute force attacks.",
        recommendation="Use key-based authentication. Disable password auth if possible. Consider changing port or using fail2ban."
    ),
    53: PortThreat(
        port=53,
        protocol="udp",
        risk_level=RiskLevel.MEDIUM,
        service_name="DNS",
        threat_description="DNS server. Can be abused for DNS amplification attacks if open resolver.",
        recommendation="Ensure it's not an open resolver. Only allow queries from local network."
    ),
    80: PortThreat(
        port=80,
        protocol="tcp",
        risk_level=RiskLevel.MEDIUM,
        service_name="HTTP",
        threat_description="Web server without encryption. Credentials and data transmitted in plain text.",
        recommendation="Use HTTPS (port 443) instead. Redirect HTTP to HTTPS."
    ),
    110: PortThreat(
        port=110,
        protocol="tcp",
        risk_level=RiskLevel.MEDIUM,
        service_name="POP3",
        threat_description="Email retrieval without encryption. Credentials sent in plain text.",
        recommendation="Use POP3S (port 995) instead for encrypted connections."
    ),
    143: PortThreat(
        port=143,
        protocol="tcp",
        risk_level=RiskLevel.MEDIUM,
        service_name="IMAP",
        threat_description="Email retrieval without encryption. Credentials sent in plain text.",
        recommendation="Use IMAPS (port 993) instead for encrypted connections."
    ),
    161: PortThreat(
        port=161,
        protocol="udp",
        risk_level=RiskLevel.MEDIUM,
        service_name="SNMP",
        threat_description="Simple Network Management Protocol. Default community strings are well-known.",
        recommendation="Change default community strings. Use SNMPv3 with authentication."
    ),
    1900: PortThreat(
        port=1900,
        protocol="udp",
        risk_level=RiskLevel.MEDIUM,
        service_name="UPnP/SSDP",
        threat_description="Universal Plug and Play. Can expose internal services to the internet.",
        recommendation="Disable UPnP on your router if not needed. Many IoT vulnerabilities involve UPnP."
    ),
    5000: PortThreat(
        port=5000,
        protocol="tcp",
        risk_level=RiskLevel.MEDIUM,
        service_name="UPnP/Various",
        threat_description="Common port for various services. Often used by NAS devices and development servers.",
        recommendation="Identify the service running. Ensure it requires authentication."
    ),
    8080: PortThreat(
        port=8080,
        protocol="tcp",
        risk_level=RiskLevel.MEDIUM,
        service_name="HTTP-Alt",
        threat_description="Alternative HTTP port. Often used for admin interfaces or proxies.",
        recommendation="Identify what's running. Ensure proper authentication."
    ),
    8443: PortThreat(
        port=8443,
        protocol="tcp",
        risk_level=RiskLevel.LOW,
        service_name="HTTPS-Alt",
        threat_description="Alternative HTTPS port. Generally safe if using valid certificates.",
        recommendation="Verify the service and ensure certificates are valid."
    ),

    # Malware/Backdoor associated ports
    31337: PortThreat(
        port=31337,
        protocol="tcp",
        risk_level=RiskLevel.CRITICAL,
        service_name="Back Orifice",
        threat_description="Classic backdoor trojan port. Should never be open.",
        recommendation="IMMEDIATE ACTION: Run antivirus scan. Investigate this device thoroughly. Consider isolating from network."
    ),
    12345: PortThreat(
        port=12345,
        protocol="tcp",
        risk_level=RiskLevel.CRITICAL,
        service_name="NetBus",
        threat_description="Known trojan/backdoor port.",
        recommendation="IMMEDIATE ACTION: Run antivirus scan. Investigate this device."
    ),
    4444: PortThreat(
        port=4444,
        protocol="tcp",
        risk_level=RiskLevel.CRITICAL,
        service_name="Metasploit/Meterpreter",
        threat_description="Default port for Metasploit reverse shells. Could indicate compromise.",
        recommendation="IMMEDIATE ACTION: Investigate this device. May be compromised."
    ),
    5554: PortThreat(
        port=5554,
        protocol="tcp",
        risk_level=RiskLevel.CRITICAL,
        service_name="Sasser Worm",
        threat_description="Port used by Sasser worm for propagation.",
        recommendation="IMMEDIATE ACTION: Run antivirus scan. Device may be infected."
    ),
    9996: PortThreat(
        port=9996,
        protocol="tcp",
        risk_level=RiskLevel.CRITICAL,
        service_name="Sasser Worm FTP",
        threat_description="FTP port used by Sasser worm.",
        recommendation="IMMEDIATE ACTION: Run antivirus scan. Device may be infected."
    ),
}


@dataclass
class DeviceThreatAssessment:
    """Complete threat assessment for a device"""
    risk_level: RiskLevel
    risk_score: int  # 0-100
    threats: List[PortThreat]
    summary: str
    top_recommendation: str
    cves: List[CVEMatchResult] = field(default_factory=list)  # Confirmed CVEs with match confidence
    warnings: List[CVEEntry] = field(default_factory=list)  # Protocol warnings (cleartext, weak auth, etc.)


class ThreatDetector:
    """Analyzes devices for potential security threats"""

    def __init__(self):
        self.threat_db = THREAT_DATABASE

    def assess_port(self, port_number: int, protocol: str = "tcp") -> Optional[PortThreat]:
        """
        Check if a port is potentially risky

        Args:
            port_number: The port number to check
            protocol: Protocol (tcp/udp)

        Returns:
            PortThreat if the port is risky, None otherwise
        """
        return self.threat_db.get(port_number)

    def assess_device(self, ports: List[Tuple[int, str, str, Optional[str], Optional[str]]]) -> DeviceThreatAssessment:
        """
        Assess overall threat level for a device based on open ports

        Args:
            ports: List of tuples: (port_number, protocol, service_name, service_product, service_version)
                   service_product and service_version are optional

        Returns:
            DeviceThreatAssessment with overall risk analysis
        """
        threats = []
        all_cve_matches: List[CVEMatchResult] = []
        all_warnings: List[CVEEntry] = []
        risk_score = 0

        # Check each port against threat database and CVE database
        for port_info in ports:
            # Handle both 3-tuple and 5-tuple formats for backward compatibility
            if len(port_info) >= 5:
                port_num, protocol, service, service_product, service_version = port_info[:5]
            elif len(port_info) >= 3:
                port_num, protocol, service = port_info[:3]
                service_product = None
                service_version = None
            else:
                continue

            threat = self.assess_port(port_num)

            # Find CVEs with strict matching (separates CVEs from warnings)
            cve_matches, port_warnings = find_cves_strict(
                service_name=service,
                service_product=service_product,
                service_version=service_version,
                port_number=port_num
            )

            if threat:
                # Add CVEs and warnings to the threat
                threat_copy = PortThreat(
                    port=threat.port,
                    protocol=threat.protocol,
                    risk_level=threat.risk_level,
                    service_name=threat.service_name,
                    threat_description=threat.threat_description,
                    recommendation=threat.recommendation,
                    cve_references=threat.cve_references.copy() if threat.cve_references else [],
                    cves=cve_matches,
                    warnings=port_warnings
                )
                threats.append(threat_copy)

                # Add to risk score based on severity
                if threat.risk_level == RiskLevel.CRITICAL:
                    risk_score += 40
                elif threat.risk_level == RiskLevel.HIGH:
                    risk_score += 25
                elif threat.risk_level == RiskLevel.MEDIUM:
                    risk_score += 10
                elif threat.risk_level == RiskLevel.LOW:
                    risk_score += 5
            elif cve_matches:
                # No threat in database, but confirmed CVEs found - create a threat entry
                highest_match = max(cve_matches, key=lambda m: m.cve.cvss_score)
                cve_risk = self._cvss_to_risk_level(highest_match.cve.cvss_score)

                threat_copy = PortThreat(
                    port=port_num,
                    protocol=protocol or "tcp",
                    risk_level=cve_risk,
                    service_name=service or "unknown",
                    threat_description=f"Known vulnerability detected: {highest_match.cve.description}",
                    recommendation=highest_match.cve.remediation,
                    cve_references=[m.cve.cve_id for m in cve_matches],
                    cves=cve_matches,
                    warnings=port_warnings
                )
                threats.append(threat_copy)

                # Add CVE-based risk score (confirmed CVEs score higher)
                if cve_risk == RiskLevel.CRITICAL:
                    risk_score += 40
                elif cve_risk == RiskLevel.HIGH:
                    risk_score += 25
                elif cve_risk == RiskLevel.MEDIUM:
                    risk_score += 10
                elif cve_risk == RiskLevel.LOW:
                    risk_score += 5
            elif port_warnings:
                # Only protocol warnings, no confirmed CVEs - add with lower severity
                highest_warning = max(port_warnings, key=lambda w: w.cvss_score)
                warning_risk = self._cvss_to_risk_level(highest_warning.cvss_score)

                threat_copy = PortThreat(
                    port=port_num,
                    protocol=protocol or "tcp",
                    risk_level=warning_risk,
                    service_name=service or "unknown",
                    threat_description=highest_warning.description,
                    recommendation=highest_warning.remediation,
                    cve_references=[],
                    cves=[],
                    warnings=port_warnings
                )
                threats.append(threat_copy)

                # Warnings score lower than confirmed CVEs
                if warning_risk == RiskLevel.CRITICAL:
                    risk_score += 15
                elif warning_risk == RiskLevel.HIGH:
                    risk_score += 10
                elif warning_risk == RiskLevel.MEDIUM:
                    risk_score += 5

            # Collect all CVE matches and warnings
            all_cve_matches.extend(cve_matches)
            for warning in port_warnings:
                if warning.cve_id not in [w.cve_id for w in all_warnings]:
                    all_warnings.append(warning)

        # Additional scoring for confirmed CVEs
        for match in all_cve_matches:
            if match.confidence == "confirmed":
                if match.cve.cvss_score >= 9.0:
                    risk_score += 10  # Bonus for confirmed critical CVEs
                elif match.cve.cvss_score >= 7.0:
                    risk_score += 5
            elif match.confidence == "likely":
                if match.cve.cvss_score >= 9.0:
                    risk_score += 3

        # Cap score at 100
        risk_score = min(risk_score, 100)

        # Determine overall risk level (only based on confirmed CVEs, not warnings)
        has_confirmed_critical = any(
            m.confidence == "confirmed" and m.cve.severity == "critical"
            for m in all_cve_matches
        )
        has_confirmed_high = any(
            m.confidence == "confirmed" and m.cve.severity == "high"
            for m in all_cve_matches
        )

        if any(t.risk_level == RiskLevel.CRITICAL for t in threats) or has_confirmed_critical:
            overall_risk = RiskLevel.CRITICAL
        elif risk_score >= 50 or any(t.risk_level == RiskLevel.HIGH for t in threats) or has_confirmed_high:
            overall_risk = RiskLevel.HIGH
        elif risk_score >= 20:
            overall_risk = RiskLevel.MEDIUM
        elif risk_score > 0:
            overall_risk = RiskLevel.LOW
        else:
            overall_risk = RiskLevel.NONE

        # Generate summary
        if not threats and not all_cve_matches and not all_warnings:
            summary = "No known risky ports detected."
            top_recommendation = "Continue monitoring with regular scans."
        else:
            critical_count = sum(1 for t in threats if t.risk_level == RiskLevel.CRITICAL)
            high_count = sum(1 for t in threats if t.risk_level == RiskLevel.HIGH)
            medium_count = sum(1 for t in threats if t.risk_level == RiskLevel.MEDIUM)

            parts = []
            if critical_count:
                parts.append(f"{critical_count} critical")
            if high_count:
                parts.append(f"{high_count} high")
            if medium_count:
                parts.append(f"{medium_count} medium")

            # Only count confirmed CVEs in summary
            confirmed_count = sum(1 for m in all_cve_matches if m.confidence == "confirmed")
            cve_info = f" ({confirmed_count} confirmed CVEs)" if confirmed_count else ""
            warning_info = f", {len(all_warnings)} warnings" if all_warnings else ""

            if parts:
                summary = f"Found {len(threats)} risky ports: {', '.join(parts)} risk{cve_info}{warning_info}."
            elif all_warnings:
                summary = f"Found {len(all_warnings)} protocol security warnings."
            else:
                summary = "No significant security issues detected."

            # Get top recommendation from highest severity threat
            sorted_threats = sorted(threats, key=lambda t: (
                t.risk_level == RiskLevel.CRITICAL,
                t.risk_level == RiskLevel.HIGH,
                t.risk_level == RiskLevel.MEDIUM
            ), reverse=True)
            top_recommendation = sorted_threats[0].recommendation if sorted_threats else ""

        # Deduplicate CVE matches
        seen_cves = set()
        unique_cve_matches = []
        for match in all_cve_matches:
            if match.cve.cve_id not in seen_cves:
                seen_cves.add(match.cve.cve_id)
                unique_cve_matches.append(match)

        # Sort CVE matches by confidence then severity
        def sort_key(m: CVEMatchResult):
            confidence_order = {"confirmed": 0, "likely": 1, "possible": 2}
            return (confidence_order.get(m.confidence, 3), -m.cve.cvss_score)

        unique_cve_matches.sort(key=sort_key)

        # Sort warnings by severity
        all_warnings.sort(key=lambda w: severity_to_score(w.severity), reverse=True)

        return DeviceThreatAssessment(
            risk_level=overall_risk,
            risk_score=risk_score,
            threats=threats,
            summary=summary,
            top_recommendation=top_recommendation,
            cves=unique_cve_matches,
            warnings=all_warnings
        )

    def _cvss_to_risk_level(self, cvss_score: float) -> RiskLevel:
        """Convert CVSS score to risk level"""
        if cvss_score >= 9.0:
            return RiskLevel.CRITICAL
        elif cvss_score >= 7.0:
            return RiskLevel.HIGH
        elif cvss_score >= 4.0:
            return RiskLevel.MEDIUM
        elif cvss_score > 0:
            return RiskLevel.LOW
        return RiskLevel.NONE

    def get_risk_color(self, risk_level: RiskLevel) -> str:
        """Get color class for risk level (for UI)"""
        colors = {
            RiskLevel.NONE: "green",
            RiskLevel.LOW: "blue",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.HIGH: "orange",
            RiskLevel.CRITICAL: "red"
        }
        return colors.get(risk_level, "gray")

    def get_all_known_threats(self) -> List[PortThreat]:
        """Get list of all known port threats"""
        return list(self.threat_db.values())
