# Network Visualization

Argus provides comprehensive network visualization tools to help you understand your network topology, monitor traffic, and identify potential issues.

## Accessing Visualizations

Navigate to **Visualization** in the sidebar to access all visualization tools. Use the tab navigation to switch between different views.

---

## Topology

Interactive network topology map showing device connections and relationships.

### Node Types

| Shape | Type | Description |
|-------|------|-------------|
| :material-diamond: Diamond | Gateway | Your router/gateway device |
| :material-square: Square | Switch | Network switches |
| :material-triangle: Triangle | Access Point | Wireless access points |
| :material-circle: Circle | Device | Regular network devices |

### Node Colors

Nodes are colored by risk level:

- :material-circle:{ style="color: #ef4444" } **Red** - Critical risk
- :material-circle:{ style="color: #f97316" } **Orange** - High risk
- :material-circle:{ style="color: #eab308" } **Yellow** - Medium risk
- :material-circle:{ style="color: #3b82f6" } **Blue** - Low risk
- :material-circle:{ style="color: #22c55e" } **Green** - Safe

### Connection Lines

- **Solid cyan lines** - Wired connections
- **Dashed purple lines** - Wireless connections

!!! tip "UniFi Integration"
    For accurate topology data showing actual switch ports and wireless connections, enable the [UniFi integration](integrations/unifi.md).

### Sidebar Panels

- **Connection Types** - Doughnut chart showing wired vs wireless distribution
- **Top Vendors** - List of most common device manufacturers
- **Device Details** - Click any node to see device information

---

## Risk Map

Visual heat map displaying all devices organized by risk level.

### Risk Categories

| Level | Color | Action Required |
|-------|-------|-----------------|
| Critical | Red | Immediate attention |
| High | Orange | Address soon |
| Medium | Yellow | Review when possible |
| Low | Blue | Monitor |
| Safe | Green | No action needed |

Click any device card to view full device details.

---

## Traffic

Monitor network bandwidth usage per device.

!!! info "Requires UniFi Integration"
    Traffic data is only available when [UniFi integration](integrations/unifi.md) is configured.

### Views

- **Top Consumers** - Devices sorted by total traffic with progress bars
- **Traffic Distribution** - Doughnut chart of bandwidth allocation
- **Upload vs Download** - Horizontal bar chart comparing TX/RX per device

### Reading Traffic Data

- **TX (Upload)** - Data sent by the device
- **RX (Download)** - Data received by the device
- Traffic is displayed in human-readable format (KB, MB, GB, TB)

---

## Wireless

Analyze your wireless network health and device connectivity.

!!! info "Requires UniFi Integration"
    Wireless data is only available when [UniFi integration](integrations/unifi.md) is configured.

### Signal Strength

Devices sorted by signal strength (weakest first) for easy troubleshooting:

| Signal (dBm) | Quality | Color |
|--------------|---------|-------|
| -30 to -50 | Excellent | Green |
| -50 to -60 | Good | Blue |
| -60 to -70 | Fair | Yellow |
| -70 to -80 | Poor | Orange |
| Below -80 | Very Poor | Red |

!!! tip "Troubleshooting Weak Signals"
    Devices at the top of the list have the weakest signal. Consider:

    - Moving the device closer to an access point
    - Adding a wireless extender or additional AP
    - Checking for interference sources

### Access Points & SSIDs

Shows each wireless network with:

- SSID name
- Number of connected clients
- Associated access point

### Signal Distribution

Bar chart showing how many devices fall into each signal quality category.

---

## DNS Analysis

Monitor DNS query patterns and blocking statistics.

!!! info "Requires Pi-hole or AdGuard"
    DNS analytics require either [Pi-hole](integrations/pihole.md) or [AdGuard Home](integrations/adguard.md) integration.

### Stats Cards

| Metric | Description |
|--------|-------------|
| Total Queries | DNS queries in last 24 hours |
| Blocked | Queries blocked by ad/tracker lists |
| Block Rate | Percentage of queries blocked |
| Devices | Number of devices making queries |

### Domain Lists

- **Top Domains** - Most frequently queried domains
- **Blocked Domains** - Most frequently blocked domains

### Query Types

Doughnut chart showing distribution of DNS query types (A, AAAA, HTTPS, PTR, etc.)

### DNS Risk Scores

Per-device risk scores based on:

- Suspicious domain queries
- Known malware/tracker domains
- Query patterns

---

## Port Matrix

Grid view showing all open ports across all devices.

### Reading the Matrix

- **Rows** - Devices (IP addresses)
- **Columns** - Port numbers
- **Cells** - Colored by port risk level

### Port Risk Levels

| Color | Risk | Examples |
|-------|------|----------|
| Red | High | Telnet (23), FTP (21), RDP (3389) |
| Orange | Medium | SMB (445), MySQL (3306) |
| Yellow | Low | HTTP (80), HTTPS (443) |
| Green | Safe | Standard services |

Hover over any cell to see service details.

---

## Timeline

Track network changes over time.

### Event Types

| Icon | Event | Description |
|------|-------|-------------|
| :material-plus-circle:{ style="color: #22c55e" } | Device Added | New device appeared |
| :material-minus-circle:{ style="color: #ef4444" } | Device Removed | Device no longer responding |
| :material-lan-connect:{ style="color: #f97316" } | Port Opened | New service exposed |
| :material-lan-disconnect:{ style="color: #3b82f6" } | Port Closed | Service no longer accessible |
| :material-swap-horizontal:{ style="color: #eab308" } | Service Changed | Version or product changed |

### Filtering

Use the date range selector to focus on specific time periods.

---

## Performance Tips

- **Large networks**: Topology rendering may take longer with 50+ devices
- **Data refresh**: Click the scan selector to load data from different scans
- **Browser performance**: Chrome/Edge recommended for best visualization performance
