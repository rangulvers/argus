"""Local CVE Database for common homelab vulnerabilities"""

from dataclasses import dataclass
from typing import List, Optional, Dict
import re


@dataclass
class CVEEntry:
    """Represents a CVE vulnerability entry"""
    cve_id: str
    description: str
    severity: str  # low, medium, high, critical
    cvss_score: float  # 0.0-10.0
    affected_services: List[str]  # Service names to match
    affected_products: List[str]  # Product names to match
    affected_versions: List[str]  # Version patterns ("*" = all, or specific ranges)
    remediation: str
    references: List[str]


# Local CVE database focusing on common homelab vulnerabilities
CVE_DATABASE: List[CVEEntry] = [
    # SMB/Windows File Sharing Vulnerabilities
    CVEEntry(
        cve_id="CVE-2017-0144",
        description="EternalBlue - Remote code execution vulnerability in Microsoft SMB v1",
        severity="critical",
        cvss_score=9.8,
        affected_services=["microsoft-ds", "smb", "netbios-ssn"],
        affected_products=["microsoft", "windows", "samba"],
        affected_versions=["*"],
        remediation="Disable SMBv1, apply MS17-010 patch, or block port 445 from untrusted networks",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"]
    ),
    CVEEntry(
        cve_id="CVE-2020-0796",
        description="SMBGhost - Remote code execution in SMB v3.1.1 compression",
        severity="critical",
        cvss_score=10.0,
        affected_services=["microsoft-ds", "smb"],
        affected_products=["windows 10", "windows server 2019"],
        affected_versions=["*"],
        remediation="Apply KB4551762 patch or disable SMBv3 compression",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-0796"]
    ),

    # RDP Vulnerabilities
    CVEEntry(
        cve_id="CVE-2019-0708",
        description="BlueKeep - Remote code execution in Remote Desktop Services",
        severity="critical",
        cvss_score=9.8,
        affected_services=["ms-wbt-server", "rdp"],
        affected_products=["windows", "remote desktop"],
        affected_versions=["*"],
        remediation="Apply security patches, enable NLA, or block RDP from internet",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"]
    ),
    CVEEntry(
        cve_id="CVE-2019-1181",
        description="DejaBlue - Remote code execution in RDP services",
        severity="critical",
        cvss_score=9.8,
        affected_services=["ms-wbt-server", "rdp"],
        affected_products=["windows"],
        affected_versions=["*"],
        remediation="Apply August 2019 security updates",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-1181"]
    ),

    # SSH Vulnerabilities
    CVEEntry(
        cve_id="CVE-2024-6387",
        description="RegreSSHion - Race condition in OpenSSH sshd allowing unauthenticated RCE",
        severity="high",
        cvss_score=8.1,
        affected_services=["ssh", "openssh"],
        affected_products=["openssh"],
        affected_versions=["8.5p1", "9.7p1"],
        remediation="Upgrade to OpenSSH 9.8p1 or later",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"]
    ),
    CVEEntry(
        cve_id="CVE-2023-38408",
        description="PKCS#11 feature in ssh-agent allows remote code execution",
        severity="critical",
        cvss_score=9.8,
        affected_services=["ssh", "openssh"],
        affected_products=["openssh"],
        affected_versions=["*"],
        remediation="Upgrade to OpenSSH 9.3p2 or later",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"]
    ),

    # Telnet Vulnerabilities
    CVEEntry(
        cve_id="CVE-TELNET-CLEARTEXT",
        description="Telnet transmits credentials in cleartext, vulnerable to MITM attacks",
        severity="high",
        cvss_score=7.5,
        affected_services=["telnet"],
        affected_products=["telnet"],
        affected_versions=["*"],
        remediation="Replace Telnet with SSH for secure remote access",
        references=["https://cwe.mitre.org/data/definitions/319.html"]
    ),

    # FTP Vulnerabilities
    CVEEntry(
        cve_id="CVE-FTP-CLEARTEXT",
        description="FTP transmits credentials in cleartext, vulnerable to credential theft",
        severity="medium",
        cvss_score=5.3,
        affected_services=["ftp"],
        affected_products=["ftp", "vsftpd", "proftpd"],
        affected_versions=["*"],
        remediation="Use SFTP or FTPS instead of plain FTP",
        references=["https://cwe.mitre.org/data/definitions/319.html"]
    ),
    CVEEntry(
        cve_id="CVE-2015-3306",
        description="ProFTPD mod_copy allows remote file copying without authentication",
        severity="critical",
        cvss_score=10.0,
        affected_services=["ftp"],
        affected_products=["proftpd"],
        affected_versions=["1.3.5"],
        remediation="Upgrade ProFTPD or disable mod_copy module",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"]
    ),

    # Database Vulnerabilities
    CVEEntry(
        cve_id="CVE-MYSQL-EXPOSED",
        description="MySQL/MariaDB exposed to network without authentication restrictions",
        severity="high",
        cvss_score=7.5,
        affected_services=["mysql", "mariadb"],
        affected_products=["mysql", "mariadb"],
        affected_versions=["*"],
        remediation="Bind to localhost, use firewall rules, require strong authentication",
        references=["https://dev.mysql.com/doc/refman/8.0/en/security.html"]
    ),
    CVEEntry(
        cve_id="CVE-REDIS-UNAUTH",
        description="Redis exposed without authentication allows remote command execution",
        severity="critical",
        cvss_score=9.8,
        affected_services=["redis"],
        affected_products=["redis"],
        affected_versions=["*"],
        remediation="Enable Redis authentication (requirepass), bind to localhost",
        references=["https://redis.io/docs/management/security/"]
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
        references=["https://www.mongodb.com/docs/manual/security/"]
    ),
    CVEEntry(
        cve_id="CVE-2021-32050",
        description="MongoDB improper input validation allows injection attacks",
        severity="high",
        cvss_score=7.5,
        affected_services=["mongodb"],
        affected_products=["mongodb"],
        affected_versions=["*"],
        remediation="Upgrade to patched version and validate inputs",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-32050"]
    ),

    # Web Server Vulnerabilities
    CVEEntry(
        cve_id="CVE-2021-44228",
        description="Log4Shell - Critical RCE in Apache Log4j via JNDI injection",
        severity="critical",
        cvss_score=10.0,
        affected_services=["http", "https", "java"],
        affected_products=["log4j", "java", "tomcat"],
        affected_versions=["2.0-beta9", "2.14.1"],
        remediation="Upgrade Log4j to 2.17.0+, or set log4j2.formatMsgNoLookups=true",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
    ),
    CVEEntry(
        cve_id="CVE-2024-27316",
        description="Apache HTTP Server HTTP/2 CONTINUATION frames DoS",
        severity="high",
        cvss_score=7.5,
        affected_services=["http", "https"],
        affected_products=["apache", "httpd"],
        affected_versions=["2.4.17", "2.4.58"],
        remediation="Upgrade Apache to 2.4.59 or later",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-27316"]
    ),
    CVEEntry(
        cve_id="CVE-2021-23017",
        description="Nginx DNS resolver vulnerability allows memory corruption",
        severity="high",
        cvss_score=7.7,
        affected_services=["http", "https"],
        affected_products=["nginx"],
        affected_versions=["0.6.18", "1.20.0"],
        remediation="Upgrade Nginx to 1.21.0 or later",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"]
    ),

    # VNC Vulnerabilities
    CVEEntry(
        cve_id="CVE-VNC-WEAK-AUTH",
        description="VNC often uses weak authentication and transmits data insecurely",
        severity="high",
        cvss_score=7.5,
        affected_services=["vnc", "rfb"],
        affected_products=["vnc", "realvnc", "tigervnc", "ultravnc"],
        affected_versions=["*"],
        remediation="Use VNC over SSH tunnel, enable strong authentication",
        references=["https://cwe.mitre.org/data/definitions/287.html"]
    ),
    CVEEntry(
        cve_id="CVE-2019-15681",
        description="LibVNC heap-based buffer overflow in HandleRFBServerMessage",
        severity="high",
        cvss_score=7.5,
        affected_services=["vnc"],
        affected_products=["libvnc", "tigervnc"],
        affected_versions=["*"],
        remediation="Upgrade to patched VNC server version",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-15681"]
    ),

    # IoT/Network Device Vulnerabilities
    CVEEntry(
        cve_id="CVE-UPNP-EXPOSED",
        description="UPnP service exposed allows automatic port forwarding and service discovery",
        severity="medium",
        cvss_score=5.3,
        affected_services=["upnp", "ssdp"],
        affected_products=["upnp"],
        affected_versions=["*"],
        remediation="Disable UPnP on router and devices, or restrict to trusted networks",
        references=["https://www.us-cert.gov/ncas/alerts/TA14-017A"]
    ),
    CVEEntry(
        cve_id="CVE-SNMP-DEFAULT",
        description="SNMP with default community strings allows information disclosure",
        severity="medium",
        cvss_score=5.3,
        affected_services=["snmp"],
        affected_products=["snmp", "net-snmp"],
        affected_versions=["*"],
        remediation="Change default community strings, use SNMPv3 with authentication",
        references=["https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/7282-12.html"]
    ),

    # Docker/Container Vulnerabilities
    CVEEntry(
        cve_id="CVE-DOCKER-EXPOSED",
        description="Docker daemon API exposed without TLS allows container escape",
        severity="critical",
        cvss_score=9.8,
        affected_services=["docker"],
        affected_products=["docker"],
        affected_versions=["*"],
        remediation="Enable TLS for Docker daemon, don't expose on network",
        references=["https://docs.docker.com/engine/security/protect-access/"]
    ),

    # Elasticsearch Vulnerabilities
    CVEEntry(
        cve_id="CVE-ELASTIC-UNAUTH",
        description="Elasticsearch exposed without authentication allows data access",
        severity="high",
        cvss_score=7.5,
        affected_services=["elasticsearch"],
        affected_products=["elasticsearch"],
        affected_versions=["*"],
        remediation="Enable X-Pack security, require authentication",
        references=["https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html"]
    ),

    # Kubernetes Vulnerabilities
    CVEEntry(
        cve_id="CVE-K8S-API-EXPOSED",
        description="Kubernetes API server exposed allows cluster takeover",
        severity="critical",
        cvss_score=9.8,
        affected_services=["kubernetes"],
        affected_products=["kubernetes", "k8s"],
        affected_versions=["*"],
        remediation="Use RBAC, don't expose API publicly, require authentication",
        references=["https://kubernetes.io/docs/concepts/security/"]
    ),

    # Memcached Vulnerabilities
    CVEEntry(
        cve_id="CVE-MEMCACHED-EXPOSED",
        description="Memcached exposed allows DDoS amplification and data theft",
        severity="high",
        cvss_score=7.5,
        affected_services=["memcache", "memcached"],
        affected_products=["memcached"],
        affected_versions=["*"],
        remediation="Bind to localhost, disable UDP, use firewall rules",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-1000115"]
    ),
]


def match_version(version: str, patterns: List[str]) -> bool:
    """Check if a version matches any of the specified patterns"""
    if not version or "*" in patterns:
        return True

    version_lower = version.lower()
    for pattern in patterns:
        pattern_lower = pattern.lower()
        # Simple substring match for now
        if pattern_lower in version_lower or version_lower in pattern_lower:
            return True
    return False


def match_product(product: str, products: List[str]) -> bool:
    """Check if a product name matches any of the specified products"""
    if not product:
        return False

    product_lower = product.lower()
    for p in products:
        p_lower = p.lower()
        if p_lower in product_lower or product_lower in p_lower:
            return True
    return False


def find_cves_for_service(
    service_name: Optional[str] = None,
    service_product: Optional[str] = None,
    service_version: Optional[str] = None,
    port_number: Optional[int] = None
) -> List[CVEEntry]:
    """Find CVEs that match a given service/product/version"""
    matches = []

    for cve in CVE_DATABASE:
        matched = False

        # Match by service name
        if service_name:
            service_lower = service_name.lower()
            for affected_service in cve.affected_services:
                if affected_service.lower() in service_lower or service_lower in affected_service.lower():
                    matched = True
                    break

        # Match by product name
        if not matched and service_product:
            if match_product(service_product, cve.affected_products):
                matched = True

        # If matched, check version if available
        if matched:
            # If version checking is implemented and version doesn't match, skip
            if service_version and cve.affected_versions != ["*"]:
                if not match_version(service_version, cve.affected_versions):
                    continue
            matches.append(cve)

    return matches


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
