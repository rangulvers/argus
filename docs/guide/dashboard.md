# Dashboard

Overview of your network's current state at a glance.

![Dashboard](../assets/argus_dashboard.png)

## Metrics Cards

| Card | Description | What to Watch |
|------|-------------|---------------|
| :material-devices: **Total Devices** | Unique devices discovered | Unexpected growth |
| :material-alert: **At Risk** | Devices with Medium+ risk | Should decrease over time |
| :material-alert-octagon: **Critical/High** | Immediate attention needed | Target: 0 |
| :material-clock: **Last Scan** | Most recent scan timestamp | Keep scans regular |

!!! tip "Dashboard Goals"
    A healthy network dashboard shows:

    - Stable device count (no unexpected additions)
    - Zero critical/high risk devices
    - Regular scan activity
    - Minimal recent changes

---

## Network Overview Charts

Real-time charts showing current network composition:

| Chart | Type | What it Shows |
|-------|------|---------------|
| :material-chart-donut: **Risk Distribution** | Doughnut | Device counts by risk level |
| :material-chart-donut: **Device Types** | Doughnut | Breakdown by vendor/category |
| :material-chart-pie: **Top Open Ports** | Polar Area | Most commonly open ports |
| :material-radar: **Security Posture** | Radar | Multi-dimensional security score |

### Security Posture Metrics

The radar chart evaluates five key areas:

- **Device Security** - Percentage of devices at low/safe risk
- **Trust Coverage** - Percentage of devices marked as trusted
- **Port Exposure** - Inverse of average open ports (fewer = better)
- **Network Stability** - Based on recent change activity
- **Monitoring** - Scan frequency and coverage

!!! tip "Target Scores"
    Aim for all metrics above 70% for a healthy security posture.

---

## Historical Trend Charts

Historical data with selectable time range (7d, 30d, 90d, 1y):

| Chart | What it Shows | Healthy Trend |
|-------|---------------|---------------|
| :material-chart-line: **Device Count** | Network growth over time | Stable or gradual |
| :material-shield: **Average Risk** | Security posture | Decreasing |
| :material-server-network: **Open Ports** | Total exposed services | Stable or decreasing |
| :material-swap-horizontal: **Changes** | Network churn rate | Low activity |

??? info "Understanding Network Churn"
    High change rates can indicate:

    - DHCP lease changes (normal)
    - Devices going online/offline (IoT often does this)
    - Someone adding new devices
    - Potential unauthorized access

---

## Latest Scan

Shows the most recent scan with:

- **Status** - Completed, Running, or Failed
- **Subnet** - Network range scanned
- **Device Count** - How many hosts found
- **Profile** - Quick, Normal, or Intensive

---

## Device Table

Quick view of discovered devices:

| Column | Description |
|--------|-------------|
| Risk indicator | Color-coded security level |
| IP Address | Network address |
| Hostname | DNS/NetBIOS name |
| Vendor | Manufacturer (from MAC OUI) |
| Ports | Count of open ports |

!!! note "Click for Details"
    Click any row to view full device details, including open ports, security analysis, and settings.

---

## Recent Changes

Track what's happening on your network:

| Type | Icon | Description |
|------|------|-------------|
| Device Added | :material-plus-circle:{ .text-green } | New host appeared |
| Device Removed | :material-minus-circle:{ .text-red } | Host no longer responding |
| Port Opened | :material-lan-connect:{ .text-orange } | New service exposed |
| Port Closed | :material-lan-disconnect:{ .text-blue } | Service no longer accessible |
| Service Changed | :material-swap-horizontal:{ .text-yellow } | Version or product changed |

!!! warning "New Device Alerts"
    Pay attention to unexpected "Device Added" changes. These could be:

    - New legitimate devices
    - Guest devices
    - **Unauthorized access**

---

## Quick Actions

| Action | Description |
|--------|-------------|
| :material-radar: **Run Scan** | Trigger a manual network scan |
| :material-weather-night: **Dark Mode** | Toggle between light and dark theme |
