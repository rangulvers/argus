"""Visualization API routes."""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import desc

from app.database import get_db
from app.models import Scan, Device, Change
from app.utils.device_icons import detect_device_type, get_device_icon_info

logger = logging.getLogger(__name__)
router = APIRouter()


def _get_risk_color(risk_level: str) -> str:
    """Get color for risk level"""
    return {
        "critical": "#dc2626",  # red-600
        "high": "#ea580c",      # orange-600
        "medium": "#ca8a04",    # yellow-600
        "low": "#16a34a",       # green-600
        "none": "#6b7280",      # gray-500
    }.get(risk_level or "none", "#6b7280")


def _get_zone_color(zone: str) -> str:
    """Get color for zone"""
    colors = ["#3b82f6", "#8b5cf6", "#ec4899", "#14b8a6", "#f97316", "#84cc16"]
    return colors[hash(zone) % len(colors)]


@router.get("/api/visualization/topology")
async def get_topology_data(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Get network topology data for visualization"""
    # Get the scan to use
    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
    else:
        scan = db.query(Scan).filter(Scan.status == "completed").order_by(desc(Scan.completed_at)).first()

    if not scan:
        return {"nodes": [], "edges": [], "groups": {}}

    devices = (
        db.query(Device)
        .options(selectinload(Device.ports))
        .filter(Device.scan_id == scan.id)
        .all()
    )

    # Build nodes and group by zone/subnet
    nodes = []
    groups = {}

    for device in devices:
        zone = device.zone or "Unknown"
        if zone not in groups:
            groups[zone] = {"color": _get_zone_color(zone), "count": 0}
        groups[zone]["count"] += 1

        # Determine node color based on risk
        node_color = _get_risk_color(device.risk_level)

        nodes.append({
            "id": device.id,
            "label": device.label or device.hostname or device.ip_address,
            "ip": device.ip_address,
            "mac": device.mac_address,
            "vendor": device.vendor,
            "hostname": device.hostname,
            "zone": zone,
            "risk_level": device.risk_level or "none",
            "risk_score": device.risk_score or 0,
            "ports_count": len(device.ports),
            "is_trusted": device.is_trusted,
            "color": node_color,
            "size": 20 + (device.risk_score or 0) * 2,  # Larger nodes = higher risk
        })

    # Create edges based on same subnet (simplified - all devices in same scan are connected to a central router node)
    edges = []
    # Add router/gateway as central node
    if nodes:
        # Detect gateway (usually .1 or .254)
        gateway_node = next(
            (n for n in nodes if n["ip"].endswith(".1") or n["ip"].endswith(".254")),
            None
        )
        gateway_id = gateway_node["id"] if gateway_node else "gateway"

        if not gateway_node:
            nodes.insert(0, {
                "id": "gateway",
                "label": "Gateway",
                "ip": scan.subnet.replace("/24", ".1") if scan.subnet else "Gateway",
                "zone": "Infrastructure",
                "risk_level": "none",
                "color": "#6b7280",
                "size": 30,
                "is_gateway": True
            })

        # Connect all devices to gateway
        for node in nodes:
            if node["id"] != gateway_id:
                edges.append({
                    "from": gateway_id,
                    "to": node["id"],
                    "color": "#4b5563"
                })

    return {
        "nodes": nodes,
        "edges": edges,
        "groups": groups,
        "scan_id": scan.id,
        "scan_date": scan.completed_at.isoformat() if scan.completed_at else None
    }


@router.get("/api/visualization/heatmap")
async def get_heatmap_data(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Get risk heatmap data for visualization"""
    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
    else:
        scan = db.query(Scan).filter(Scan.status == "completed").order_by(desc(Scan.completed_at)).first()

    if not scan:
        return {"devices": [], "summary": {}}

    devices = (
        db.query(Device)
        .options(selectinload(Device.ports))
        .filter(Device.scan_id == scan.id)
        .all()
    )

    # Group by risk level
    risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}

    heatmap_data = []
    for device in devices:
        risk = device.risk_level or "none"
        risk_summary[risk] = risk_summary.get(risk, 0) + 1

        # Get device icon type
        ports = [p.port_number for p in device.ports] if device.ports else []
        icon_type = detect_device_type(
            vendor=device.vendor,
            hostname=device.hostname,
            os_name=device.os_name,
            device_type=device.device_type,
            ports=ports,
            mac_address=device.mac_address,
            ip_address=device.ip_address,
        )
        icon_info = get_device_icon_info(icon_type)

        heatmap_data.append({
            "id": device.id,
            "ip": device.ip_address,
            "label": device.label or device.hostname or device.ip_address,
            "zone": device.zone or "Unknown",
            "risk_level": risk,
            "risk_score": device.risk_score or 0,
            "ports_count": len(device.ports),
            "is_trusted": device.is_trusted,
            "threat_summary": device.threat_summary,
            "icon_type": icon_type,
            "device_type_label": icon_info["label"],
        })

    # Sort by risk score descending
    heatmap_data.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "devices": heatmap_data,
        "summary": risk_summary,
        "scan_id": scan.id
    }


@router.get("/api/visualization/port-matrix")
async def get_port_matrix_data(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Get port/service matrix data for visualization"""
    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
    else:
        scan = db.query(Scan).filter(Scan.status == "completed").order_by(desc(Scan.completed_at)).first()

    if not scan:
        return {"devices": [], "ports": [], "matrix": []}

    devices = (
        db.query(Device)
        .options(selectinload(Device.ports))
        .filter(Device.scan_id == scan.id)
        .all()
    )

    # Collect all unique ports
    all_ports = set()
    device_ports = {}

    for device in devices:
        device_ports[device.id] = {
            "id": device.id,
            "ip": device.ip_address,
            "label": device.label or device.hostname or device.ip_address,
            "ports": {}
        }
        for port in device.ports:
            all_ports.add(port.port_number)
            device_ports[device.id]["ports"][port.port_number] = {
                "service": port.service_name,
                "state": port.state,
                "product": port.service_product
            }

    # Sort ports
    sorted_ports = sorted(list(all_ports))

    # Build matrix
    matrix = []
    for device_id, device_data in device_ports.items():
        row = {
            "device_id": device_data["id"],
            "device_ip": device_data["ip"],
            "device_label": device_data["label"],
            "ports": []
        }
        for port in sorted_ports:
            if port in device_data["ports"]:
                row["ports"].append({
                    "port": port,
                    "open": True,
                    "service": device_data["ports"][port]["service"],
                    "product": device_data["ports"][port]["product"]
                })
            else:
                row["ports"].append({"port": port, "open": False})
        matrix.append(row)

    return {
        "ports": sorted_ports,
        "matrix": matrix,
        "scan_id": scan.id
    }


@router.get("/api/visualization/timeline")
async def get_timeline_data(
    device_id: Optional[int] = None,
    days: int = 30,
    db: Session = Depends(get_db)
):
    """Get device timeline data for visualization"""
    from datetime import datetime, timedelta

    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Get changes within the time range
    query = db.query(Change).filter(Change.detected_at >= cutoff_date)

    if device_id:
        device = db.query(Device).filter(Device.id == device_id).first()
        if device:
            query = query.filter(
                (Change.device_ip == device.ip_address) |
                (Change.device_mac == device.mac_address)
            )

    changes = query.order_by(Change.detected_at).all()

    timeline_events = []
    for change in changes:
        timeline_events.append({
            "id": change.id,
            "type": change.change_type,
            "severity": change.severity,
            "device_ip": change.device_ip,
            "device_mac": change.device_mac,
            "port": change.port_number,
            "description": change.description,
            "timestamp": change.detected_at.isoformat(),
            "scan_id": change.scan_id
        })

    # Also get scan history for context
    scans = db.query(Scan).filter(
        Scan.started_at >= cutoff_date,
        Scan.status == "completed"
    ).order_by(Scan.started_at).all()

    scan_events = [
        {
            "id": f"scan-{scan.id}",
            "type": "scan",
            "timestamp": scan.completed_at.isoformat() if scan.completed_at else scan.started_at.isoformat(),
            "devices_found": scan.devices_found,
            "profile": scan.scan_profile
        }
        for scan in scans
    ]

    return {
        "changes": timeline_events,
        "scans": scan_events,
        "days": days
    }


@router.get("/api/visualization/network-insights")
async def get_network_insights(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Get comprehensive network insights for enhanced visualizations.

    Returns data for:
    - Enhanced topology with UniFi connection data
    - Vendor distribution
    - Connection types (wired/wireless)
    - Traffic analysis
    - DNS query analysis (Pi-hole/AdGuard)
    - Signal strength for wireless devices
    """
    # Get the scan to use
    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
    else:
        scan = db.query(Scan).filter(
            Scan.status == "completed",
            Scan.scan_type == "network"
        ).order_by(desc(Scan.started_at)).first()

    if not scan:
        return {
            "has_data": False,
            "vendor_distribution": {},
            "connection_types": {},
            "traffic_data": [],
            "dns_analysis": {},
            "signal_strength": [],
            "topology_enhanced": {"nodes": [], "edges": [], "switches": [], "access_points": []}
        }

    devices = db.query(Device).filter(Device.scan_id == scan.id).all()

    # ===== Vendor Distribution =====
    vendor_counts = {}
    for device in devices:
        vendor = device.vendor or "Unknown"
        # Simplify vendor names (take first word/company name)
        if vendor != "Unknown":
            vendor = vendor.split()[0] if " " in vendor else vendor
            vendor = vendor.replace(",", "").replace("Inc.", "").replace("Ltd.", "")
        vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

    # Sort by count and take top 10
    vendor_distribution = dict(sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10])

    # ===== Connection Types & Traffic & Signal Strength =====
    connection_types = {"wired": 0, "wireless": 0, "unknown": 0}
    traffic_data = []
    signal_strength_data = []
    switches = {}  # switch_mac -> {name, port_count, devices: []}
    access_points = {}  # ssid -> {devices: [], channel, etc.}

    for device in devices:
        integrations = {}
        if device.threat_details and isinstance(device.threat_details, dict):
            integrations = device.threat_details.get("integrations", {})

        unifi_data = integrations.get("unifi", {})

        # Connection type
        conn_type = unifi_data.get("connection_type", "unknown")
        if conn_type in connection_types:
            connection_types[conn_type] += 1
        else:
            connection_types["unknown"] += 1

        # Traffic data (only for devices with UniFi data)
        if unifi_data and unifi_data.get("traffic"):
            traffic = unifi_data["traffic"]
            traffic_data.append({
                "device_id": device.id,
                "label": device.label or device.hostname or device.ip_address,
                "ip": device.ip_address,
                "tx_bytes": traffic.get("tx_bytes", 0),
                "rx_bytes": traffic.get("rx_bytes", 0),
                "total_bytes": traffic.get("tx_bytes", 0) + traffic.get("rx_bytes", 0),
                "is_online": unifi_data.get("is_online", True)
            })

        # Wireless signal strength
        if unifi_data.get("wireless"):
            wireless = unifi_data["wireless"]
            signal_strength_data.append({
                "device_id": device.id,
                "label": device.label or device.hostname or device.ip_address,
                "ip": device.ip_address,
                "signal": wireless.get("signal_strength", 0),
                "ssid": wireless.get("ssid", "Unknown"),
                "channel": wireless.get("channel"),
                "radio": wireless.get("radio", ""),
                "tx_rate": wireless.get("tx_rate", 0),
                "rx_rate": wireless.get("rx_rate", 0)
            })

            # Group by access point (SSID)
            ssid = wireless.get("ssid", "Unknown")
            if ssid not in access_points:
                access_points[ssid] = {
                    "ssid": ssid,
                    "channel": wireless.get("channel"),
                    "radio": wireless.get("radio"),
                    "devices": []
                }
            access_points[ssid]["devices"].append({
                "id": device.id,
                "label": device.label or device.hostname or device.ip_address,
                "signal": wireless.get("signal_strength", 0)
            })

        # Wired connections - group by switch
        if unifi_data.get("wired"):
            wired = unifi_data["wired"]
            switch_mac = wired.get("switch_mac", "unknown")
            if switch_mac not in switches:
                switches[switch_mac] = {
                    "mac": switch_mac,
                    "devices": []
                }
            switches[switch_mac]["devices"].append({
                "id": device.id,
                "label": device.label or device.hostname or device.ip_address,
                "port": wired.get("switch_port")
            })

    # Sort traffic data by total bytes (top consumers)
    traffic_data.sort(key=lambda x: x["total_bytes"], reverse=True)
    traffic_data = traffic_data[:15]  # Top 15

    # Sort signal strength by signal (weakest first for troubleshooting)
    signal_strength_data.sort(key=lambda x: x["signal"])

    # ===== DNS Analysis =====
    dns_analysis = {
        "total_queries": 0,
        "total_blocked": 0,
        "devices_with_dns": 0,
        "top_domains": {},
        "top_blocked": {},
        "query_types": {},
        "risk_scores": []
    }

    for device in devices:
        integrations = {}
        if device.threat_details and isinstance(device.threat_details, dict):
            integrations = device.threat_details.get("integrations", {})

        # Check Pi-hole or AdGuard
        dns_data = integrations.get("pihole") or integrations.get("adguard")
        if dns_data:
            dns_analysis["devices_with_dns"] += 1
            dns_analysis["total_queries"] += dns_data.get("queries_24h", 0)
            dns_analysis["total_blocked"] += dns_data.get("blocked_24h", 0)

            # Aggregate top domains
            for domain_info in dns_data.get("top_domains", []):
                domain = domain_info.get("domain", "")
                count = domain_info.get("count", 0)
                dns_analysis["top_domains"][domain] = dns_analysis["top_domains"].get(domain, 0) + count

            # Aggregate blocked domains
            for domain_info in dns_data.get("blocked_domains", []):
                domain = domain_info.get("domain", "")
                count = domain_info.get("count", 0)
                dns_analysis["top_blocked"][domain] = dns_analysis["top_blocked"].get(domain, 0) + count

            # Query types
            for qtype, count in dns_data.get("query_types", {}).items():
                dns_analysis["query_types"][qtype] = dns_analysis["query_types"].get(qtype, 0) + count

            # Risk scores
            if dns_data.get("dns_risk_score") is not None:
                dns_analysis["risk_scores"].append({
                    "device_id": device.id,
                    "label": device.label or device.hostname or device.ip_address,
                    "score": dns_data.get("dns_risk_score", 0)
                })

    # Sort and limit
    dns_analysis["top_domains"] = dict(sorted(
        dns_analysis["top_domains"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10])
    dns_analysis["top_blocked"] = dict(sorted(
        dns_analysis["top_blocked"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10])
    dns_analysis["risk_scores"].sort(key=lambda x: x["score"], reverse=True)
    dns_analysis["risk_scores"] = dns_analysis["risk_scores"][:10]

    # ===== Enhanced Topology =====
    # Build topology with actual connection data from UniFi
    topology_nodes = []
    topology_edges = []

    # Find gateway
    gateway = None
    for device in devices:
        if device.ip_address and (device.ip_address.endswith(".1") or device.ip_address.endswith(".254")):
            gateway = device
            break

    gateway_id = gateway.id if gateway else "gateway"

    # Add gateway node
    if not gateway:
        topology_nodes.append({
            "id": "gateway",
            "label": "Gateway",
            "type": "gateway",
            "group": "infrastructure"
        })

    # Add switch nodes
    for idx, (switch_mac, switch_info) in enumerate(switches.items()):
        switch_id = f"switch-{idx}"
        topology_nodes.append({
            "id": switch_id,
            "label": f"Switch",
            "type": "switch",
            "mac": switch_mac,
            "group": "infrastructure",
            "device_count": len(switch_info["devices"])
        })
        # Connect switch to gateway
        topology_edges.append({
            "from": gateway_id,
            "to": switch_id,
            "type": "wired"
        })
        # Connect devices to switch
        for dev in switch_info["devices"]:
            topology_edges.append({
                "from": switch_id,
                "to": dev["id"],
                "type": "wired",
                "port": dev.get("port")
            })

    # Add AP nodes
    for idx, (ssid, ap_info) in enumerate(access_points.items()):
        ap_id = f"ap-{idx}"
        topology_nodes.append({
            "id": ap_id,
            "label": ssid,
            "type": "access_point",
            "group": "infrastructure",
            "channel": ap_info.get("channel"),
            "device_count": len(ap_info["devices"])
        })
        # Connect AP to gateway
        topology_edges.append({
            "from": gateway_id,
            "to": ap_id,
            "type": "wired"
        })
        # Connect wireless devices to AP
        for dev in ap_info["devices"]:
            topology_edges.append({
                "from": ap_id,
                "to": dev["id"],
                "type": "wireless",
                "signal": dev.get("signal")
            })

    # Add all device nodes
    for device in devices:
        integrations = {}
        if device.threat_details and isinstance(device.threat_details, dict):
            integrations = device.threat_details.get("integrations", {})

        unifi_data = integrations.get("unifi", {})

        node = {
            "id": device.id,
            "label": device.label or device.hostname or device.ip_address,
            "ip": device.ip_address,
            "mac": device.mac_address,
            "type": device.device_type or "unknown",
            "risk_level": device.risk_level or "none",
            "risk_score": device.risk_score or 0,
            "is_trusted": device.is_trusted,
            "is_online": unifi_data.get("is_online", True),
            "connection_type": unifi_data.get("connection_type", "unknown"),
            "group": device.zone or "default"
        }
        topology_nodes.append(node)

        # If device has no switch/AP connection, connect directly to gateway
        has_connection = any(e["to"] == device.id for e in topology_edges)
        if not has_connection and device.id != gateway_id:
            topology_edges.append({
                "from": gateway_id,
                "to": device.id,
                "type": "unknown"
            })

    return {
        "has_data": True,
        "scan_id": scan.id,
        "total_devices": len(devices),
        "vendor_distribution": vendor_distribution,
        "connection_types": connection_types,
        "traffic_data": traffic_data,
        "dns_analysis": dns_analysis,
        "signal_strength": signal_strength_data,
        "topology_enhanced": {
            "nodes": topology_nodes,
            "edges": topology_edges,
            "switches": list(switches.values()),
            "access_points": list(access_points.values())
        }
    }
