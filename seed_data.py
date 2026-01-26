#!/usr/bin/env python3
"""
Seed script for development - populates database with realistic dummy data.

Usage:
    python seed_data.py          # Seed with default data
    python seed_data.py --reset  # Clear DB and reseed
"""

import argparse
import random
from datetime import datetime, timedelta
from app.database import SessionLocal, init_db, engine, Base
from app.models import Scan, Device, Port, Change, DeviceHistory


# Sample integration data generators
def generate_unifi_data(device_type, is_wireless=None):
    """Generate realistic UniFi integration data"""
    if is_wireless is None:
        is_wireless = device_type in ["Smartphone", "Tablet", "Laptop"]

    data = {
        "is_online": random.choice([True, True, True, False]),  # 75% online
        "is_guest": random.choice([False, False, False, True]),  # 25% guest
        "connection_type": "wireless" if is_wireless else "wired",
        "uptime_seconds": random.randint(3600, 864000),  # 1 hour to 10 days
        "traffic": {
            "tx_bytes": random.randint(1000000, 50000000000),
            "rx_bytes": random.randint(1000000, 100000000000),
            "tx_packets": random.randint(1000, 10000000),
            "rx_packets": random.randint(1000, 20000000),
        },
    }

    if is_wireless:
        data["wireless"] = {
            "ssid": random.choice(["HomeNetwork", "HomeNetwork_5G", "IoT_Network", "Guest_WiFi"]),
            "signal_strength": random.randint(-80, -30),
            "channel": random.choice([1, 6, 11, 36, 40, 44, 48, 149, 153]),
            "radio": random.choice(["ng", "na", "ac", "ax"]),
            "tx_rate": random.choice([54, 144, 300, 433, 867, 1200]),
            "rx_rate": random.choice([54, 144, 300, 433, 867, 1200]),
        }
    else:
        data["wired"] = {
            "switch_mac": ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)]),
            "switch_port": random.randint(1, 24),
        }

    data["network"] = {
        "name": random.choice(["LAN", "IoT", "Guest", "Management"]),
        "vlan": random.choice([1, 10, 20, 30, None]),
    }

    return data


def generate_pihole_data():
    """Generate realistic Pi-hole integration data"""
    queries = random.randint(100, 50000)
    blocked = random.randint(0, int(queries * 0.3))

    return {
        "queries_24h": queries,
        "blocked_24h": blocked,
        "blocked_percentage": round((blocked / queries * 100) if queries > 0 else 0, 1),
        "unique_domains": random.randint(20, 500),
        "dns_risk_score": random.randint(0, 100),
        "top_domains": [
            {"domain": "google.com", "count": random.randint(50, 500)},
            {"domain": "facebook.com", "count": random.randint(20, 200)},
            {"domain": "amazonaws.com", "count": random.randint(30, 300)},
            {"domain": "cloudflare.com", "count": random.randint(10, 100)},
            {"domain": "apple.com", "count": random.randint(10, 150)},
        ],
        "blocked_domains": [
            {"domain": "ads.google.com", "count": random.randint(5, 50)},
            {"domain": "tracking.facebook.com", "count": random.randint(3, 30)},
            {"domain": "telemetry.microsoft.com", "count": random.randint(2, 20)},
        ],
        "suspicious_domains": random.choice([
            [],
            [],
            [{"domain": "suspicious-tracker.xyz", "reason": "Known tracker"}],
        ]),
        "query_types": {
            "A": random.randint(50, 80),
            "AAAA": random.randint(10, 30),
            "HTTPS": random.randint(5, 15),
            "PTR": random.randint(1, 5),
        },
        "last_query": datetime.utcnow().isoformat(),
    }


def generate_adguard_data():
    """Generate realistic AdGuard integration data"""
    queries = random.randint(100, 50000)
    blocked = random.randint(0, int(queries * 0.25))

    return {
        "queries_24h": queries,
        "blocked_24h": blocked,
        "blocked_percentage": round((blocked / queries * 100) if queries > 0 else 0, 1),
        "unique_domains": random.randint(20, 500),
        "dns_risk_score": random.randint(0, 100),
        "top_domains": [
            {"domain": "microsoft.com", "count": random.randint(50, 400)},
            {"domain": "apple.com", "count": random.randint(30, 250)},
            {"domain": "netflix.com", "count": random.randint(20, 150)},
            {"domain": "spotify.com", "count": random.randint(10, 100)},
        ],
        "blocked_domains": [
            {"domain": "ads.doubleclick.net", "count": random.randint(10, 100)},
            {"domain": "analytics.google.com", "count": random.randint(5, 50)},
        ],
        "suspicious_domains": [],
        "query_types": {
            "A": random.randint(50, 80),
            "AAAA": random.randint(10, 30),
            "HTTPS": random.randint(5, 15),
        },
        "last_query": datetime.utcnow().isoformat(),
    }


# Realistic device data for home/office networks
DEVICES_DATA = [
    # Routers/Gateways
    {
        "hostname": "router.local",
        "vendor": "NETGEAR",
        "device_type": "Router",
        "os_name": "Linux 3.x",
        "ports": [(80, "http", "nginx", "1.18.0"), (443, "https", "nginx", "1.18.0"), (53, "domain", "dnsmasq", "2.85")],
        "risk_level": "low",
        "is_trusted": True,
    },
    {
        "hostname": "unifi-controller",
        "vendor": "Ubiquiti Networks",
        "device_type": "Network Controller",
        "os_name": "Linux 4.x",
        "ports": [(8443, "https", "UniFi Controller", "7.4.162"), (8080, "http", None, None), (22, "ssh", "OpenSSH", "8.9")],
        "risk_level": "medium",
        "is_trusted": True,
    },
    # NAS Devices
    {
        "hostname": "synology-nas",
        "vendor": "Synology",
        "device_type": "NAS",
        "os_name": "Linux 4.4.x (Synology DSM)",
        "ports": [(5000, "http", "Synology DSM", "7.2"), (5001, "https", "Synology DSM", "7.2"), (22, "ssh", "OpenSSH", "8.4"), (445, "microsoft-ds", "Samba", "4.15"), (139, "netbios-ssn", "Samba", "4.15")],
        "risk_level": "medium",
        "is_trusted": True,
        "label": "Main Storage",
    },
    {
        "hostname": "qnap-backup",
        "vendor": "QNAP Systems",
        "device_type": "NAS",
        "os_name": "Linux 4.x (QTS)",
        "ports": [(8080, "http", "QNAP QTS", "5.1"), (443, "https", "QNAP QTS", "5.1"), (22, "ssh", "OpenSSH", "7.9")],
        "risk_level": "low",
        "is_trusted": True,
        "label": "Backup NAS",
    },
    # Smart Home
    {
        "hostname": "philips-hue-bridge",
        "vendor": "Philips Lighting",
        "device_type": "Smart Home Hub",
        "os_name": "Linux embedded",
        "ports": [(80, "http", "lighttpd", "1.4"), (443, "https", "lighttpd", "1.4")],
        "risk_level": "none",
        "is_trusted": True,
    },
    {
        "hostname": "homeassistant",
        "vendor": "Raspberry Pi Foundation",
        "device_type": "Smart Home Server",
        "os_name": "Linux 5.15 (Home Assistant OS)",
        "ports": [(8123, "http", "Home Assistant", "2024.1"), (22, "ssh", "OpenSSH", "9.0")],
        "risk_level": "low",
        "is_trusted": True,
        "label": "Home Assistant",
    },
    # Computers
    {
        "hostname": "macbook-pro.local",
        "vendor": "Apple",
        "device_type": "Laptop",
        "os_name": "macOS 14.x (Sonoma)",
        "ports": [(22, "ssh", "OpenSSH", "9.4"), (5000, "upnp", None, None)],
        "risk_level": "none",
        "is_trusted": True,
        "label": "Work Laptop",
    },
    {
        "hostname": "gaming-pc",
        "vendor": "Intel Corporate",
        "device_type": "Desktop",
        "os_name": "Windows 11",
        "ports": [(135, "msrpc", "Microsoft RPC", None), (139, "netbios-ssn", None, None), (445, "microsoft-ds", "SMB", "3.1.1"), (3389, "ms-wbt-server", "Microsoft Terminal Services", None)],
        "risk_level": "medium",
        "is_trusted": True,
        "label": "Gaming PC",
    },
    {
        "hostname": "ubuntu-server",
        "vendor": "Dell",
        "device_type": "Server",
        "os_name": "Linux 5.15 (Ubuntu 22.04)",
        "ports": [(22, "ssh", "OpenSSH", "8.9"), (80, "http", "Apache", "2.4.52"), (443, "https", "Apache", "2.4.52"), (3306, "mysql", "MySQL", "8.0.35")],
        "risk_level": "medium",
        "is_trusted": True,
        "label": "Dev Server",
    },
    # Mobile Devices
    {
        "hostname": "iPhone",
        "vendor": "Apple",
        "device_type": "Smartphone",
        "os_name": "iOS 17.x",
        "ports": [(62078, "iphone-sync", None, None)],
        "risk_level": "none",
        "is_trusted": True,
    },
    {
        "hostname": "android-tablet",
        "vendor": "Samsung Electronics",
        "device_type": "Tablet",
        "os_name": "Android 14",
        "ports": [],
        "risk_level": "none",
        "is_trusted": True,
    },
    # IoT/Printers
    {
        "hostname": "hp-printer",
        "vendor": "HP Inc",
        "device_type": "Printer",
        "os_name": "HP Printer Firmware",
        "ports": [(80, "http", "HP Embedded Web Server", None), (443, "https", None, None), (631, "ipp", "CUPS", "2.4"), (9100, "jetdirect", None, None)],
        "risk_level": "low",
        "is_trusted": True,
        "label": "Office Printer",
    },
    {
        "hostname": "canon-scanner",
        "vendor": "Canon",
        "device_type": "Scanner",
        "os_name": "Embedded",
        "ports": [(80, "http", None, None)],
        "risk_level": "none",
        "is_trusted": False,
    },
    # Media Devices
    {
        "hostname": "plex-server",
        "vendor": "Intel Corporate",
        "device_type": "Media Server",
        "os_name": "Linux 5.x",
        "ports": [(32400, "http", "Plex Media Server", "1.40"), (22, "ssh", "OpenSSH", "8.9")],
        "risk_level": "low",
        "is_trusted": True,
        "label": "Plex Server",
    },
    {
        "hostname": "samsung-tv",
        "vendor": "Samsung Electronics",
        "device_type": "Smart TV",
        "os_name": "Tizen OS",
        "ports": [(8001, "http", "Samsung TV", None), (8002, "https", None, None)],
        "risk_level": "none",
        "is_trusted": True,
    },
    {
        "hostname": "roku-streaming",
        "vendor": "Roku",
        "device_type": "Streaming Device",
        "os_name": "Roku OS",
        "ports": [(8060, "http", "Roku ECP", None)],
        "risk_level": "none",
        "is_trusted": True,
    },
    # Potentially Risky Devices
    {
        "hostname": "old-webcam",
        "vendor": "Shenzhen Bilian Electronic",
        "device_type": "IP Camera",
        "os_name": "Linux 2.6",
        "ports": [(80, "http", "GoAhead WebServer", "2.5"), (554, "rtsp", None, None), (23, "telnet", "BusyBox telnetd", None)],
        "risk_level": "critical",
        "is_trusted": False,
        "notes": "Old camera with telnet enabled - security risk!",
    },
    {
        "hostname": "iot-sensor",
        "vendor": "Espressif",
        "device_type": "IoT Sensor",
        "os_name": "FreeRTOS",
        "ports": [(80, "http", "ESP WebServer", None)],
        "risk_level": "low",
        "is_trusted": False,
    },
    # Unknown/Suspicious
    {
        "hostname": None,
        "vendor": "Unknown",
        "device_type": None,
        "os_name": None,
        "ports": [(22, "ssh", None, None), (80, "http", None, None)],
        "risk_level": "high",
        "is_trusted": False,
        "notes": "Unknown device appeared on network",
    },
    {
        "hostname": "guest-laptop",
        "vendor": "Lenovo",
        "device_type": "Laptop",
        "os_name": "Windows 10",
        "ports": [(135, "msrpc", None, None), (445, "microsoft-ds", None, None)],
        "risk_level": "medium",
        "is_trusted": False,
        "label": "Guest Device",
    },
]


def generate_mac():
    """Generate a random MAC address"""
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])


def generate_ip(base="192.168.1", start=1):
    """Generate sequential IPs"""
    counter = start
    while True:
        yield f"{base}.{counter}"
        counter += 1


def clear_database():
    """Drop all tables and recreate"""
    print("Clearing database...")
    Base.metadata.drop_all(bind=engine)
    init_db()
    print("Database cleared and recreated.")


def seed_database():
    """Populate database with dummy data"""
    db = SessionLocal()

    try:
        # Check if data already exists
        existing_scans = db.query(Scan).count()
        if existing_scans > 0:
            print(f"Database already has {existing_scans} scans. Use --reset to clear first.")
            return False

        print("Seeding database with dummy data...")

        ip_gen = generate_ip()
        now = datetime.utcnow()

        # Create 3 scans over the past week
        scans_data = [
            {"offset_days": 7, "profile": "intensive", "device_count": 18},
            {"offset_days": 3, "profile": "normal", "device_count": 19},
            {"offset_days": 0, "profile": "normal", "device_count": 20},
        ]

        scans = []
        for scan_info in scans_data:
            scan_time = now - timedelta(days=scan_info["offset_days"], hours=random.randint(0, 12))
            scan = Scan(
                started_at=scan_time,
                completed_at=scan_time + timedelta(minutes=random.randint(2, 10)),
                status="completed",
                scan_type="network",
                scan_profile=scan_info["profile"],
                subnet="192.168.1.0/24",
                devices_found=scan_info["device_count"],
            )
            db.add(scan)
            db.flush()
            scans.append(scan)
            print(f"  Created scan #{scan.id} ({scan_info['profile']}) - {scan_info['device_count']} devices")

        # Create devices for each scan
        mac_addresses = {i: generate_mac() for i in range(len(DEVICES_DATA))}

        for scan_idx, scan in enumerate(scans):
            ip_gen = generate_ip()
            # Later scans have more devices (simulating new devices appearing)
            device_count = scans_data[scan_idx]["device_count"]

            for i, device_data in enumerate(DEVICES_DATA[:device_count]):
                ip = next(ip_gen)
                mac = mac_addresses[i]

                # Calculate risk score based on risk level
                risk_scores = {"none": 0, "low": 15, "medium": 45, "high": 70, "critical": 90}
                risk_score = risk_scores.get(device_data["risk_level"], 0)
                risk_score += random.randint(-5, 5)  # Add some variance
                risk_score = max(0, min(100, risk_score))

                # Generate integration data for some devices
                # UniFi: ~70% of devices, Pi-hole: ~50%, AdGuard: ~30%
                threat_details = {"integrations": {}}
                device_type = device_data.get("device_type")

                # UniFi data for most devices (simulate managed network)
                if random.random() < 0.7:
                    threat_details["integrations"]["unifi"] = generate_unifi_data(device_type)

                # Pi-hole OR AdGuard (typically you'd have one or the other)
                # ~50% have Pi-hole data
                if random.random() < 0.5:
                    threat_details["integrations"]["pihole"] = generate_pihole_data()
                # ~30% have AdGuard data (some overlap is fine for demo)
                elif random.random() < 0.4:
                    threat_details["integrations"]["adguard"] = generate_adguard_data()

                # Clean up empty integrations dict
                if not threat_details["integrations"]:
                    threat_details = None

                device = Device(
                    scan_id=scan.id,
                    ip_address=ip,
                    mac_address=mac,
                    hostname=device_data.get("hostname"),
                    vendor=device_data.get("vendor"),
                    device_type=device_data.get("device_type"),
                    os_name=device_data.get("os_name"),
                    os_accuracy=random.randint(85, 100) if device_data.get("os_name") else None,
                    status="up",
                    first_seen=scan.started_at - timedelta(days=random.randint(0, 30)),
                    last_seen=scan.started_at,
                    label=device_data.get("label"),
                    is_trusted=device_data.get("is_trusted", False),
                    notes=device_data.get("notes"),
                    risk_level=device_data["risk_level"],
                    risk_score=risk_score,
                    threat_summary=f"Risk level: {device_data['risk_level']}" if device_data["risk_level"] != "none" else None,
                    threat_details=threat_details,
                )
                db.add(device)
                db.flush()

                # Add ports
                for port_data in device_data.get("ports", []):
                    port_num, service, product, version = port_data
                    port = Port(
                        device_id=device.id,
                        port_number=port_num,
                        protocol="tcp",
                        state="open",
                        service_name=service,
                        service_product=product,
                        service_version=version,
                    )
                    db.add(port)

            print(f"    Added {device_count} devices to scan #{scan.id}")

        # Create some changes between scans
        changes_data = [
            {
                "scan_id": scans[1].id,
                "change_type": "device_added",
                "severity": "warning",
                "device_ip": "192.168.1.19",
                "device_mac": mac_addresses[18],
                "description": "New device detected: iot-sensor (Espressif)",
            },
            {
                "scan_id": scans[2].id,
                "change_type": "device_added",
                "severity": "critical",
                "device_ip": "192.168.1.20",
                "device_mac": mac_addresses[19],
                "description": "New unknown device detected with open ports",
            },
            {
                "scan_id": scans[2].id,
                "change_type": "port_opened",
                "severity": "warning",
                "device_ip": "192.168.1.8",
                "port_number": 3389,
                "protocol": "tcp",
                "description": "RDP port opened on gaming-pc",
            },
            {
                "scan_id": scans[1].id,
                "change_type": "service_changed",
                "severity": "info",
                "device_ip": "192.168.1.3",
                "port_number": 5000,
                "old_value": "Synology DSM 7.1",
                "new_value": "Synology DSM 7.2",
                "description": "Synology DSM updated from 7.1 to 7.2",
            },
        ]

        for change_data in changes_data:
            change = Change(
                scan_id=change_data["scan_id"],
                change_type=change_data["change_type"],
                severity=change_data["severity"],
                device_ip=change_data.get("device_ip"),
                device_mac=change_data.get("device_mac"),
                port_number=change_data.get("port_number"),
                protocol=change_data.get("protocol"),
                old_value=change_data.get("old_value"),
                new_value=change_data.get("new_value"),
                description=change_data["description"],
                detected_at=db.query(Scan).get(change_data["scan_id"]).completed_at,
            )
            db.add(change)

        print(f"  Created {len(changes_data)} change records")

        # Create device history entries
        for i, device_data in enumerate(DEVICES_DATA):
            history = DeviceHistory(
                mac_address=mac_addresses[i],
                last_ip=f"192.168.1.{i+1}",
                last_hostname=device_data.get("hostname"),
                first_seen=now - timedelta(days=random.randint(7, 90)),
                last_seen=now,
                times_seen=random.randint(3, 20),
                label=device_data.get("label"),
                is_trusted=device_data.get("is_trusted", False),
                notes=device_data.get("notes"),
            )
            db.add(history)

        print(f"  Created {len(DEVICES_DATA)} device history entries")

        db.commit()
        print("\nDatabase seeded successfully!")
        print(f"  - {len(scans)} scans")
        print(f"  - {sum(s['device_count'] for s in scans_data)} total device records")
        print(f"  - {len(changes_data)} changes")
        print(f"  - {len(DEVICES_DATA)} device history entries")
        return True

    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
        raise
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="Seed the Argus database with dummy data")
    parser.add_argument("--reset", action="store_true", help="Clear database before seeding")
    args = parser.parse_args()

    # Ensure tables exist
    init_db()

    if args.reset:
        clear_database()

    seed_database()


if __name__ == "__main__":
    main()
