"""Local CVE Database for common homelab vulnerabilities

Implements strict matching:
- Real CVEs require product AND version match
- Protocol warnings are kept separate for cleartext/weak security issues
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from enum import Enum
import re
import logging

logger = logging.getLogger(__name__)

# Try to import packaging for version comparison, fall back to basic comparison
try:
    from packaging import version as pkg_version
    HAS_PACKAGING = True
except ImportError:
    HAS_PACKAGING = False
    logger.warning("packaging library not installed, version comparison will be basic")


class EntryType(str, Enum):
    """Type of CVE database entry"""
    CVE = "cve"                    # Real CVE with NVD reference
    PROTOCOL_WARNING = "warning"   # Protocol-level security warning (cleartext, weak auth)


@dataclass
class CVEEntry:
    """Represents a CVE vulnerability entry"""
    cve_id: str
    description: str
    severity: str  # low, medium, high, critical
    cvss_score: float  # 0.0-10.0
    affected_services: List[str]  # Service names to match
    affected_products: List[str]  # Product names to match
    affected_versions: List[str]  # Version patterns (legacy, prefer version_ranges)
    remediation: str
    references: List[str]

    # New fields for strict matching
    entry_type: EntryType = EntryType.CVE
    affected_ports: Optional[List[int]] = None  # Ports this CVE applies to (None = any)
    requires_product_match: bool = True  # Must detect product to show this CVE
    requires_version_match: bool = False  # Must match version range to show
    version_ranges: Optional[List[Tuple[Optional[str], Optional[str]]]] = None  # [(min, max), ...]


@dataclass
class CVEMatchResult:
    """Result of CVE matching with confidence info"""
    cve: CVEEntry
    confidence: str  # "confirmed", "likely", "possible"
    matched_product: Optional[str] = None
    matched_version: Optional[str] = None


def parse_version_safe(ver_str: str) -> Optional[object]:
    """Safely parse a version string"""
    if not ver_str:
        return None

    try:
        # Clean common prefixes/suffixes
        ver_clean = re.sub(r'^[vV]', '', ver_str)
        # Remove trailing non-numeric parts for comparison
        ver_clean = re.sub(r'[a-zA-Z_-]+\d*$', '', ver_clean)
        ver_clean = ver_clean.rstrip('.')

        if HAS_PACKAGING:
            return pkg_version.parse(ver_clean)
        else:
            # Basic tuple comparison fallback
            parts = re.split(r'[.\-_]', ver_clean)
            return tuple(int(p) if p.isdigit() else p for p in parts if p)
    except Exception:
        return None


def version_compare(v1: object, v2: object) -> int:
    """Compare two parsed versions. Returns: -1 if v1<v2, 0 if equal, 1 if v1>v2"""
    if HAS_PACKAGING:
        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
        return 0
    else:
        # Tuple comparison for fallback
        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
        return 0


def match_version_range(
    detected_version: str,
    version_ranges: List[Tuple[Optional[str], Optional[str]]]
) -> bool:
    """
    Check if detected version falls within any of the specified ranges.

    version_ranges: List of (min_version, max_version) tuples
                   None means unbounded on that side
    """
    if not detected_version or not version_ranges:
        return False

    detected = parse_version_safe(detected_version)
    if detected is None:
        return False  # Can't parse = no match (strict policy)

    for min_ver, max_ver in version_ranges:
        min_ok = True
        max_ok = True

        if min_ver:
            min_parsed = parse_version_safe(min_ver)
            if min_parsed:
                min_ok = version_compare(detected, min_parsed) >= 0

        if max_ver:
            max_parsed = parse_version_safe(max_ver)
            if max_parsed:
                max_ok = version_compare(detected, max_parsed) <= 0

        if min_ok and max_ok:
            return True

    return False


def strict_product_match(
    detected_product: str,
    affected_products: List[str]
) -> bool:
    """Strict product matching - requires clear match, not loose substring"""
    if not detected_product or not affected_products:
        return False

    detected_lower = detected_product.lower()

    for product in affected_products:
        product_lower = product.lower()
        # Exact match
        if detected_lower == product_lower:
            return True
        # Product is a complete word within detected string
        if re.search(rf'\b{re.escape(product_lower)}\b', detected_lower):
            return True
        # Detected is a complete word within product (e.g., "openssh" in "openssh-server")
        if re.search(rf'\b{re.escape(detected_lower)}\b', product_lower):
            return True

    return False


def strict_service_match(
    detected_service: str,
    affected_services: List[str]
) -> bool:
    """Strict service matching for protocol warnings"""
    if not detected_service or not affected_services:
        return False

    detected_lower = detected_service.lower()

    for service in affected_services:
        service_lower = service.lower()
        if detected_lower == service_lower:
            return True
        # Handle common variations (e.g., "ssh" matches "openssh")
        if service_lower in detected_lower or detected_lower in service_lower:
            return True

    return False


def find_cves_strict(
    service_name: Optional[str] = None,
    service_product: Optional[str] = None,
    service_version: Optional[str] = None,
    port_number: Optional[int] = None
) -> Tuple[List[CVEMatchResult], List[CVEEntry]]:
    """
    Find CVEs with strict matching requirements.

    Returns:
        Tuple of (confirmed_cves, protocol_warnings)
        - confirmed_cves: CVEs where product AND version matched
        - protocol_warnings: Protocol-level warnings (shown based on port/service)
    """
    confirmed_cves: List[CVEMatchResult] = []
    protocol_warnings: List[CVEEntry] = []

    for cve in CVE_DATABASE:
        # Handle protocol warnings separately - always match by port/service
        if cve.entry_type == EntryType.PROTOCOL_WARNING:
            # Check port restriction
            if cve.affected_ports and port_number and port_number not in cve.affected_ports:
                continue

            # Match by service name
            if service_name and strict_service_match(service_name, cve.affected_services):
                protocol_warnings.append(cve)
            continue

        # For real CVEs: require strict matching

        # Check port restriction first (fast filter)
        if cve.affected_ports and port_number and port_number not in cve.affected_ports:
            continue

        # If product match is required, we need service_product
        if cve.requires_product_match:
            if not service_product:
                continue  # Skip - no product info available to confirm

            if not strict_product_match(service_product, cve.affected_products):
                continue  # Product doesn't match

        # Match version if required
        if cve.requires_version_match:
            if not service_version:
                continue  # Skip - no version info to confirm

            if cve.version_ranges:
                if not match_version_range(service_version, cve.version_ranges):
                    continue  # Version not in affected range

        # Determine confidence level
        product_matched = service_product and strict_product_match(service_product, cve.affected_products)
        version_matched = False

        if service_version and cve.version_ranges:
            version_matched = match_version_range(service_version, cve.version_ranges)

        if product_matched and version_matched:
            confidence = "confirmed"
        elif product_matched:
            confidence = "likely"
        else:
            confidence = "possible"

        confirmed_cves.append(CVEMatchResult(
            cve=cve,
            confidence=confidence,
            matched_product=service_product if product_matched else None,
            matched_version=service_version if version_matched else None
        ))

    return confirmed_cves, protocol_warnings


# ============================================================================
# PROTOCOL WARNINGS - Match by service/port, no product required
# ============================================================================

PROTOCOL_WARNINGS: List[CVEEntry] = [
    CVEEntry(
        cve_id="WARN-TELNET-CLEARTEXT",
        description="Telnet transmits credentials in cleartext, vulnerable to MITM attacks",
        severity="high",
        cvss_score=7.5,
        affected_services=["telnet"],
        affected_products=[],
        affected_versions=["*"],
        remediation="Replace Telnet with SSH for secure remote access",
        references=["https://cwe.mitre.org/data/definitions/319.html"],
        entry_type=EntryType.PROTOCOL_WARNING,
        affected_ports=[23],
        requires_product_match=False,
        requires_version_match=False
    ),
    CVEEntry(
        cve_id="WARN-FTP-CLEARTEXT",
        description="FTP transmits credentials in cleartext, vulnerable to credential theft",
        severity="medium",
        cvss_score=5.3,
        affected_services=["ftp"],
        affected_products=[],
        affected_versions=["*"],
        remediation="Use SFTP or FTPS instead of plain FTP",
        references=["https://cwe.mitre.org/data/definitions/319.html"],
        entry_type=EntryType.PROTOCOL_WARNING,
        affected_ports=[21],
        requires_product_match=False,
        requires_version_match=False
    ),
    CVEEntry(
        cve_id="WARN-VNC-WEAK-AUTH",
        description="VNC often uses weak authentication and transmits data insecurely",
        severity="high",
        cvss_score=7.5,
        affected_services=["vnc", "rfb"],
        affected_products=[],
        affected_versions=["*"],
        remediation="Use VNC over SSH tunnel, enable strong authentication",
        references=["https://cwe.mitre.org/data/definitions/287.html"],
        entry_type=EntryType.PROTOCOL_WARNING,
        affected_ports=[5900, 5901, 5902, 5903],
        requires_product_match=False,
        requires_version_match=False
    ),
    CVEEntry(
        cve_id="WARN-SNMP-DEFAULT",
        description="SNMP with default community strings allows information disclosure",
        severity="medium",
        cvss_score=5.3,
        affected_services=["snmp"],
        affected_products=[],
        affected_versions=["*"],
        remediation="Change default community strings, use SNMPv3 with authentication",
        references=["https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/7282-12.html"],
        entry_type=EntryType.PROTOCOL_WARNING,
        affected_ports=[161, 162],
        requires_product_match=False,
        requires_version_match=False
    ),
    CVEEntry(
        cve_id="WARN-UPNP-EXPOSED",
        description="UPnP service exposed allows automatic port forwarding and service discovery",
        severity="medium",
        cvss_score=5.3,
        affected_services=["upnp", "ssdp"],
        affected_products=[],
        affected_versions=["*"],
        remediation="Disable UPnP on router and devices, or restrict to trusted networks",
        references=["https://www.us-cert.gov/ncas/alerts/TA14-017A"],
        entry_type=EntryType.PROTOCOL_WARNING,
        affected_ports=[1900, 5000],
        requires_product_match=False,
        requires_version_match=False
    ),
]

# ============================================================================
# REAL CVEs - Require product (and optionally version) match
# ============================================================================

REAL_CVES: List[CVEEntry] = [
    # --- SSH Vulnerabilities ---
    CVEEntry(
        cve_id="CVE-2024-6387",
        description="RegreSSHion - Race condition in OpenSSH sshd allowing unauthenticated RCE",
        severity="high",
        cvss_score=8.1,
        affected_services=["ssh"],
        affected_products=["openssh"],
        affected_versions=[],
        remediation="Upgrade to OpenSSH 9.8p1 or later",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
        entry_type=EntryType.CVE,
        affected_ports=[22],
        requires_product_match=True,
        requires_version_match=True,
        version_ranges=[("8.5", "9.7")]  # Affected: 8.5p1 to 9.7p1
    ),
    CVEEntry(
        cve_id="CVE-2023-38408",
        description="PKCS#11 feature in ssh-agent allows remote code execution via forwarded agent",
        severity="critical",
        cvss_score=9.8,
        affected_services=["ssh"],
        affected_products=["openssh"],
        affected_versions=[],
        remediation="Upgrade to OpenSSH 9.3p2 or later",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
        entry_type=EntryType.CVE,
        affected_ports=[22],
        requires_product_match=True,
        requires_version_match=True,
        version_ranges=[("5.5", "9.3")]  # Affected versions
    ),

    # --- SMB/Windows Vulnerabilities ---
    CVEEntry(
        cve_id="CVE-2017-0144",
        description="EternalBlue - Remote code execution vulnerability in Microsoft SMB v1",
        severity="critical",
        cvss_score=9.8,
        affected_services=["microsoft-ds", "smb", "netbios-ssn"],
        affected_products=["microsoft", "windows", "samba"],
        affected_versions=[],
        remediation="Disable SMBv1, apply MS17-010 patch, or block port 445 from untrusted networks",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
        entry_type=EntryType.CVE,
        affected_ports=[445, 139],
        requires_product_match=True,
        requires_version_match=False  # Affects many versions, hard to detect
    ),
    CVEEntry(
        cve_id="CVE-2020-0796",
        description="SMBGhost - Remote code execution in SMB v3.1.1 compression",
        severity="critical",
        cvss_score=10.0,
        affected_services=["microsoft-ds", "smb"],
        affected_products=["windows 10", "windows server"],
        affected_versions=[],
        remediation="Apply KB4551762 patch or disable SMBv3 compression",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-0796"],
        entry_type=EntryType.CVE,
        affected_ports=[445],
        requires_product_match=True,
        requires_version_match=False
    ),

    # --- RDP Vulnerabilities ---
    CVEEntry(
        cve_id="CVE-2019-0708",
        description="BlueKeep - Remote code execution in Remote Desktop Services",
        severity="critical",
        cvss_score=9.8,
        affected_services=["ms-wbt-server", "rdp"],
        affected_products=["windows", "remote desktop"],
        affected_versions=[],
        remediation="Apply security patches, enable NLA, or block RDP from internet",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
        entry_type=EntryType.CVE,
        affected_ports=[3389],
        requires_product_match=True,
        requires_version_match=False
    ),

    # --- Web Server Vulnerabilities ---
    CVEEntry(
        cve_id="CVE-2021-44228",
        description="Log4Shell - Critical RCE in Apache Log4j via JNDI injection",
        severity="critical",
        cvss_score=10.0,
        affected_services=["http", "https"],
        affected_products=["log4j", "tomcat", "java"],
        affected_versions=[],
        remediation="Upgrade Log4j to 2.17.0+, or set log4j2.formatMsgNoLookups=true",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        entry_type=EntryType.CVE,
        affected_ports=[80, 443, 8080, 8443, 9200],  # HTTP and common app ports
        requires_product_match=True,  # Must detect Log4j/Tomcat/Java
        requires_version_match=True,
        version_ranges=[("2.0", "2.14.1")]  # Log4j 2.0-beta9 to 2.14.1
    ),
    CVEEntry(
        cve_id="CVE-2024-27316",
        description="Apache HTTP Server HTTP/2 CONTINUATION frames DoS",
        severity="high",
        cvss_score=7.5,
        affected_services=["http", "https"],
        affected_products=["apache", "httpd"],
        affected_versions=[],
        remediation="Upgrade Apache to 2.4.59 or later",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-27316"],
        entry_type=EntryType.CVE,
        affected_ports=[80, 443, 8080, 8443],
        requires_product_match=True,
        requires_version_match=True,
        version_ranges=[("2.4.17", "2.4.58")]
    ),
    CVEEntry(
        cve_id="CVE-2021-23017",
        description="Nginx DNS resolver vulnerability allows memory corruption",
        severity="high",
        cvss_score=7.7,
        affected_services=["http", "https"],
        affected_products=["nginx"],
        affected_versions=[],
        remediation="Upgrade Nginx to 1.21.0 or later",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
        entry_type=EntryType.CVE,
        affected_ports=[80, 443, 8080],
        requires_product_match=True,
        requires_version_match=True,
        version_ranges=[("0.6.18", "1.20.0")]
    ),

    # --- FTP Vulnerabilities ---
    CVEEntry(
        cve_id="CVE-2015-3306",
        description="ProFTPD mod_copy allows remote file copying without authentication",
        severity="critical",
        cvss_score=10.0,
        affected_services=["ftp"],
        affected_products=["proftpd"],
        affected_versions=[],
        remediation="Upgrade ProFTPD or disable mod_copy module",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"],
        entry_type=EntryType.CVE,
        affected_ports=[21],
        requires_product_match=True,
        requires_version_match=True,
        version_ranges=[("1.3.5", "1.3.5")]
    ),

    # --- Database Vulnerabilities (require product match, not version) ---
    CVEEntry(
        cve_id="CVE-REDIS-UNAUTH",
        description="Redis exposed without authentication allows remote command execution",
        severity="critical",
        cvss_score=9.8,
        affected_services=["redis"],
        affected_products=["redis"],
        affected_versions=["*"],
        remediation="Enable Redis authentication (requirepass), bind to localhost",
        references=["https://redis.io/docs/management/security/"],
        entry_type=EntryType.CVE,
        affected_ports=[6379],
        requires_product_match=True,
        requires_version_match=False  # All versions without auth are vulnerable
    ),
    CVEEntry(
        cve_id="CVE-MONGODB-UNAUTH",
        description="MongoDB exposed without authentication allows unauthorized data access",
        severity="critical",
        cvss_score=9.8,
        affected_services=["mongodb", "mongod"],
        affected_products=["mongodb"],
        affected_versions=["*"],
        remediation="Enable authentication, bind to localhost or use firewall",
        references=["https://www.mongodb.com/docs/manual/security/"],
        entry_type=EntryType.CVE,
        affected_ports=[27017, 27018],
        requires_product_match=True,
        requires_version_match=False
    ),
    CVEEntry(
        cve_id="CVE-MYSQL-EXPOSED",
        description="MySQL/MariaDB exposed to network without authentication restrictions",
        severity="high",
        cvss_score=7.5,
        affected_services=["mysql", "mariadb"],
        affected_products=["mysql", "mariadb"],
        affected_versions=["*"],
        remediation="Bind to localhost, use firewall rules, require strong authentication",
        references=["https://dev.mysql.com/doc/refman/8.0/en/security.html"],
        entry_type=EntryType.CVE,
        affected_ports=[3306],
        requires_product_match=True,
        requires_version_match=False
    ),

    # --- VNC Vulnerabilities ---
    CVEEntry(
        cve_id="CVE-2019-15681",
        description="LibVNC heap-based buffer overflow in HandleRFBServerMessage",
        severity="high",
        cvss_score=7.5,
        affected_services=["vnc"],
        affected_products=["libvnc", "tigervnc"],
        affected_versions=[],
        remediation="Upgrade to patched VNC server version",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-15681"],
        entry_type=EntryType.CVE,
        affected_ports=[5900, 5901],
        requires_product_match=True,
        requires_version_match=False
    ),

    # --- Container/Orchestration Vulnerabilities ---
    CVEEntry(
        cve_id="CVE-DOCKER-EXPOSED",
        description="Docker daemon API exposed without TLS allows container escape",
        severity="critical",
        cvss_score=9.8,
        affected_services=["docker"],
        affected_products=["docker"],
        affected_versions=["*"],
        remediation="Enable TLS for Docker daemon, don't expose on network",
        references=["https://docs.docker.com/engine/security/protect-access/"],
        entry_type=EntryType.CVE,
        affected_ports=[2375, 2376],
        requires_product_match=True,
        requires_version_match=False
    ),
    CVEEntry(
        cve_id="CVE-K8S-API-EXPOSED",
        description="Kubernetes API server exposed allows cluster takeover",
        severity="critical",
        cvss_score=9.8,
        affected_services=["kubernetes"],
        affected_products=["kubernetes", "k8s"],
        affected_versions=["*"],
        remediation="Use RBAC, don't expose API publicly, require authentication",
        references=["https://kubernetes.io/docs/concepts/security/"],
        entry_type=EntryType.CVE,
        affected_ports=[6443, 8443],
        requires_product_match=True,
        requires_version_match=False
    ),

    # --- Other Services ---
    CVEEntry(
        cve_id="CVE-ELASTIC-UNAUTH",
        description="Elasticsearch exposed without authentication allows data access",
        severity="high",
        cvss_score=7.5,
        affected_services=["elasticsearch"],
        affected_products=["elasticsearch"],
        affected_versions=["*"],
        remediation="Enable X-Pack security, require authentication",
        references=["https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html"],
        entry_type=EntryType.CVE,
        affected_ports=[9200, 9300],
        requires_product_match=True,
        requires_version_match=False
    ),
    CVEEntry(
        cve_id="CVE-MEMCACHED-EXPOSED",
        description="Memcached exposed allows DDoS amplification and data theft",
        severity="high",
        cvss_score=7.5,
        affected_services=["memcache", "memcached"],
        affected_products=["memcached"],
        affected_versions=["*"],
        remediation="Bind to localhost, disable UDP, use firewall rules",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-1000115"],
        entry_type=EntryType.CVE,
        affected_ports=[11211],
        requires_product_match=True,
        requires_version_match=False
    ),
]

# Combined database
CVE_DATABASE = PROTOCOL_WARNINGS + REAL_CVES


# ============================================================================
# Legacy functions for backward compatibility
# ============================================================================

def find_cves_for_service(
    service_name: Optional[str] = None,
    service_product: Optional[str] = None,
    service_version: Optional[str] = None,
    port_number: Optional[int] = None
) -> List[CVEEntry]:
    """
    Legacy function - returns only confirmed CVEs (not warnings).
    Use find_cves_strict() for full functionality.
    """
    cve_matches, _ = find_cves_strict(service_name, service_product, service_version, port_number)
    return [m.cve for m in cve_matches]


def get_cve_by_id(cve_id: str) -> Optional[CVEEntry]:
    """Get a specific CVE by ID"""
    for cve in CVE_DATABASE:
        if cve.cve_id.upper() == cve_id.upper():
            return cve
    return None


def severity_to_score(severity: str) -> int:
    """Convert severity string to numeric score for sorting"""
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1
    }.get(severity.lower(), 0)
