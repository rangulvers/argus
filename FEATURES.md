# Argus Feature Roadmap

This document outlines planned features for Argus, a homelab network security monitoring application. Features are prioritized based on security impact and usefulness for home/small office networks.

## Priority Legend

| Priority | Label | Description |
|----------|-------|-------------|
| **P0** | Critical | Essential security features, should be implemented first |
| **P1** | High | Important features that significantly improve usability |
| **P2** | Medium | Nice-to-have features that enhance the experience |
| **P3** | Low | Polish and convenience features |

## Complexity Legend

| Symbol | Complexity | Estimated Effort |
|--------|------------|------------------|
| `[S]` | Small | Few hours |
| `[M]` | Medium | 1-2 days |
| `[L]` | Large | 3-5 days |
| `[XL]` | Extra Large | 1+ weeks |

---

## P0 - Critical Features

### 1. Authentication & Access Control

Currently, Argus has no authentication. Anyone with network access can view your entire network topology and security posture.

| Feature | Complexity | Description |
|---------|------------|-------------|
| **User Authentication** | `[M]` | Login system with username/password. Single admin user is sufficient for homelab. Store hashed passwords with bcrypt. |
| **Session Management** | `[S]` | Secure session cookies with expiration. "Remember me" option for convenience. |
| **API Key Authentication** | `[S]` | Generate API keys for CLI and external integrations. Keys should be revocable. |
| **Audit Logging** | `[M]` | Log all user actions (scans triggered, settings changed, devices modified) with timestamps. Essential for security monitoring. |

**Why P0:** Without authentication, any device on your network can access sensitive security data. This is a fundamental security issue.

---

### 2. Alerting & Notifications

The Alert model exists but notification delivery is not implemented. This is critical for a security monitoring tool.

| Feature | Complexity | Description |
|---------|------------|-------------|
| **Email Notifications (SMTP)** | `[M]` | Send alerts via email. Support for Gmail, custom SMTP, and common providers. Include scan summaries and threat alerts. |
| **Webhook Notifications** | `[S]` | POST alerts to custom URLs. Enables integration with Discord, Slack, Teams, and custom systems. Include JSON payload with alert details. |
| **Push Notifications** | `[M]` | Support for Ntfy, Gotify, Pushover, and Apprise. Essential for mobile alerts in homelab setups. |
| **Alert Rules & Thresholds** | `[M]` | Configure what triggers alerts: new device, new open port, risk level changes, specific ports, device offline. Customizable thresholds. |
| **Alert Acknowledgment** | `[S]` | Mark alerts as acknowledged. Snooze alerts for specific devices or time periods. Prevents alert fatigue. |
| **Alert Digest/Summary** | `[S]` | Option to batch alerts into periodic summaries (hourly, daily) instead of immediate notifications. |

**Why P0:** A security monitoring tool that can't notify you of threats is just a log viewer. Real-time alerting is essential.

---

## P1 - High Priority Features

### 3. Device Management

Users need better control over device information and organization.

| Feature | Complexity | Description |
|---------|------------|-------------|
| **Edit Device from UI** | `[S]` | Edit device label, notes, and trusted status directly from the device detail page. Currently requires direct DB access. |
| **Device Zones/Groups** | `[M]` | Categorize devices into zones: IoT, Servers, Workstations, Guests, Untrusted. Filter views by zone. Different alert rules per zone. |
| **Expected Device Baseline** | `[M]` | Define expected devices for your network. Alert when unknown device appears. Critical for detecting intruders. |
| **Bulk Device Operations** | `[S]` | Select multiple devices to bulk update: mark as trusted, assign to zone, add label prefix. |
| **Device Documentation** | `[S]` | Rich notes field with markdown support. Document device purpose, credentials location, maintenance notes. |
| **Device Offline Detection** | `[M]` | Track when known devices go offline. Alert if critical device (NAS, router) disappears. Configurable grace period. |

---

### 4. Reporting & Export

Essential for documentation, compliance, and external analysis.

| Feature | Complexity | Description |
|---------|------------|-------------|
| **CSV Export** | `[S]` | Export devices, scans, and changes to CSV. Filterable by date range, risk level, zone. |
| **JSON Export API** | `[S]` | Full data export via API endpoint. Enables external tool integration and backup. |
| **PDF Security Report** | `[L]` | Generate printable security assessment report. Include: executive summary, device inventory, risk overview, open ports, recommendations. |
| **Scheduled Reports** | `[M]` | Email weekly/monthly security summaries. Include: new devices, changes, risk trends, top threats. |
| **Historical Trend Charts** | `[M]` | Visualize device count, risk score, and open ports over time. Identify security posture trends. |
| **Scan History Retention** | `[S]` | Configure how long to keep scan history. Auto-cleanup old data to manage database size. |

---

### 5. Advanced Scanning

Enhance scanning capabilities for complex home networks.

| Feature | Complexity | Description |
|---------|------------|-------------|
| **Multi-Subnet Support** | `[M]` | Scan multiple subnets (e.g., main LAN, IoT VLAN, guest network). Separate or combined views. |
| **Subnet Auto-Discovery** | `[M]` | Detect available subnets from routing table. Suggest networks to scan. |
| **Custom Threat Rules** | `[M]` | Add custom port/service threat mappings. Define risk levels for ports specific to your setup. |
| **Scan Exclusion List** | `[S]` | Exclude specific IPs or MAC addresses from scans. Useful for sensitive devices that shouldn't be scanned. |
| **CVE Database Integration** | `[L]` | Cross-reference detected services with CVE database. Alert on known vulnerabilities. Pull from NVD or vulners.com API. |
| **Service-Specific Checks** | `[L]` | Basic vulnerability checks for common services: default credentials detection, SSL certificate validation, version-based vulnerability flags. |
| **Scan Profiles Custom** | `[S]` | Create custom scan profiles beyond quick/normal/intensive. Save nmap arguments as reusable profiles. |

---

## P2 - Medium Priority Features

### 6. Network Visualization

Visual representation of network topology and security posture.

| Feature | Complexity | Description |
|---------|------------|-------------|
| **Network Topology Map** | `[L]` | Interactive network diagram showing devices and connections. Group by subnet/zone. Click to view device details. |
| **Risk Heat Map** | `[M]` | Visual grid showing device risk levels. Quick identification of problem areas. Color-coded by risk score. |
| **Port/Service Matrix** | `[M]` | Matrix view showing which devices have which ports open. Quickly identify exposed services across network. |
| **Device Timeline** | `[M]` | Visual timeline of device appearances, changes, and alerts. Track device behavior over time. |

---

### 7. Network Intelligence

Deeper network monitoring beyond port scanning.

| Feature | Complexity | Description |
|---------|------------|-------------|
| **ARP Table Monitoring** | `[M]` | Monitor ARP table for changes. Detect ARP spoofing attempts. Alert on MAC address conflicts. |
| **DHCP Lease Integration** | `[M]` | Import DHCP leases from router (support for common routers/Pi-hole). Auto-populate hostnames. |
| **Pi-hole Integration** | `[M]` | Pull DNS query logs from Pi-hole. Show which devices query which domains. Identify suspicious DNS activity. |
| **Wake-on-LAN** | `[S]` | Send WoL packets to wake devices. Useful for scanning devices that are normally off. |
| **mDNS/Bonjour Discovery** | `[M]` | Discover services advertised via mDNS. Identify printers, smart home devices, media servers. |
| **SNMP Discovery** | `[L]` | Query SNMP-enabled devices for detailed info. Useful for network equipment, NAS devices, printers. |

---

### 8. Integrations

Connect Argus with other homelab tools.

| Feature | Complexity | Description |
|---------|------------|-------------|
| **Prometheus Metrics** | `[M]` | `/metrics` endpoint with device counts, risk scores, scan stats. Enable Grafana dashboards. |
| **Grafana Dashboard** | `[S]` | Pre-built Grafana dashboard JSON for Argus metrics. Quick visualization setup. |
| **Home Assistant Integration** | `[M]` | MQTT or REST sensors for HA. Show device presence, new device alerts, security status in HA dashboard. |
| **Uptime Kuma Integration** | `[S]` | Push device status to Uptime Kuma. Monitor device availability alongside other services. |
| **Syslog Export** | `[M]` | Export alerts and changes to syslog. Enable integration with SIEM tools and log aggregators. |
| **Netbox Sync** | `[L]` | Two-way sync with Netbox for device documentation. Import known devices, export discoveries. |

---

## P3 - Low Priority Features

### 9. UX Improvements

Polish and convenience features.

| Feature | Complexity | Description |
|---------|------------|-------------|
| **Dark Mode** | `[S]` | Dark theme option. Essential for late-night homelab maintenance. |
| **Mobile Responsive** | `[M]` | Improved mobile layout. Check scan status and view alerts from phone. |
| **Keyboard Shortcuts** | `[S]` | Navigation shortcuts: `s` for scan, `d` for devices, `/` for search. |
| **Customizable Dashboard** | `[M]` | Drag-and-drop dashboard widgets. Show what matters to you. |
| **Real-time Scan Progress** | `[M]` | Live progress indicator during scans. Show hosts discovered, ports scanned. WebSocket or SSE updates. |
| **Device Icons** | `[S]` | Auto-assign icons based on device type/vendor. Visual identification at a glance. |
| **Quick Actions** | `[S]` | One-click actions from device list: scan, mark trusted, add to zone, copy IP. |

---

### 10. Operations & Maintenance

Tools for managing Argus itself.

| Feature | Complexity | Description |
|---------|------------|-------------|
| **Database Backup/Restore** | `[S]` | One-click database backup. Scheduled automatic backups. Easy restore process. |
| **Configuration Export/Import** | `[S]` | Export/import settings as YAML. Easy migration and backup of configuration. |
| **Data Retention Cleanup** | `[S]` | Automatic cleanup of old scans based on retention policy. Keep database size manageable. |
| **Health Dashboard** | `[M]` | System health: database size, last scan time, scheduler status, disk space. |
| **Log Viewer** | `[M]` | View application logs from web UI. Filter by level, search for errors. |
| **Update Checker** | `[S]` | Check for new Argus versions. Notification when updates available. |

---

## Feature Requests & Ideas Backlog

Features that might be useful but need more consideration:

- **Network Speed Testing**: Periodic speed tests to ISP, track performance over time
- **Certificate Monitoring**: Track SSL certificates on network devices, alert on expiration
- **Compliance Templates**: Pre-built checks for CIS benchmarks, PCI-DSS basics
- **Multi-User Support**: Multiple users with role-based permissions
- **Agent Mode**: Lightweight agent for scanning remote networks, report to central Argus
- **Container Scanning**: Discover and inventory Docker containers on hosts
- **WiFi Client Tracking**: Integration with UniFi/OpenWRT for wireless client monitoring
- **Bandwidth Monitoring**: SNMP-based bandwidth tracking for network devices
- **MAC Address Randomization Detection**: Identify devices using random MACs

---

## Implementation Notes

### Recommended Implementation Order

1. **Phase 1 (Security Foundation)**
   - User Authentication
   - API Key Authentication
   - Edit Device from UI
   - Email Notifications

2. **Phase 2 (Core Enhancements)**
   - Webhook Notifications
   - Push Notifications (Ntfy)
   - Device Zones/Groups
   - CSV Export
   - Multi-Subnet Support

3. **Phase 3 (Intelligence)**
   - Expected Device Baseline
   - Alert Rules & Thresholds
   - Historical Trend Charts
   - Prometheus Metrics

4. **Phase 4 (Polish)**
   - Dark Mode
   - Network Topology Map
   - PDF Reports
   - Home Assistant Integration

### Technical Considerations

- **Authentication**: Use FastAPI's security utilities with OAuth2PasswordBearer
- **Notifications**: Consider using Apprise library for unified notification handling
- **Charts**: Use Chart.js or Plotly for frontend visualizations
- **Network Map**: vis.js or D3.js for interactive topology
- **PDF Generation**: WeasyPrint or ReportLab for Python PDF generation
- **Metrics**: prometheus_client library for /metrics endpoint

---

## Contributing

When implementing features:

1. Update this document to mark features as "In Progress" or "Completed"
2. Add implementation notes and any deviations from the plan
3. Update CHANGELOG.md with feature additions
4. Add relevant tests for new functionality
