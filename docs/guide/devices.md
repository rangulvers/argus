# Devices

Device inventory and management.

![Device Details](../assets/argus_device_details.png)

## Device List

| Column | Description |
|--------|-------------|
| :material-shield: **Risk** | Security risk level (color-coded) |
| :material-ip: **IP** | Network address |
| :material-dns: **Hostname** | DNS/NetBIOS name |
| :material-tag: **Label** | Your custom name |
| :material-factory: **Vendor** | OUI-based manufacturer |
| :material-folder: **Zone** | Network segment |
| :material-server-network: **Ports** | Open port count |

---

## Filters

### Quick Filters

| Filter | Options | Use Case |
|--------|---------|----------|
| :material-magnify: **Search** | IP, hostname, MAC, vendor, label | Find specific device |
| :material-alert: **Risk Level** | Critical, High, Medium, Low, None | Focus on risky devices |
| :material-check: **Trusted** | All, Trusted, Untrusted | Show/hide known devices |
| :material-folder: **Zone** | Your configured zones | Filter by segment |

### Advanced Filters

??? info "Port Filtering"
    Find devices with specific ports open:

    - Single port: `22`
    - Multiple ports: `80,443`
    - Port range: `8000-9000`

    Example: Filter by `22` to find all SSH servers.

??? info "Combining Filters"
    Filters stack together. For example:

    - Zone: `IoT` + Risk: `High` = High-risk IoT devices
    - Search: `proxmox` + Ports: `8006` = Proxmox web interfaces

---

## Quick Actions

Context menu (:material-dots-vertical:) on each row:

| Action | Description |
|--------|-------------|
| :material-content-copy: **Copy IP** | Copy IP to clipboard |
| :material-content-copy: **Copy MAC** | Copy MAC address |
| :material-radar: **Scan Device** | Run targeted scan |
| :material-shield-check: **Toggle Trusted** | Mark as trusted/untrusted |
| :material-open-in-new: **View Details** | Open device detail page |

---

## Device Details

Click any device to see the full detail page.

### Info Tab

| Field | Description |
|-------|-------------|
| IP Address | Current network address |
| MAC Address | Hardware address |
| Hostname | DNS/NetBIOS name |
| Vendor | Manufacturer (from OUI lookup) |
| OS | Operating system (if detected) |
| First Seen | When device was first discovered |
| Last Seen | Most recent scan appearance |
| Risk Score | Calculated security risk |

### Ports Tab

| Field | Description |
|-------|-------------|
| Port | Number and protocol (TCP/UDP) |
| State | `open`, `filtered`, `closed` |
| Service | Service name (ssh, http, etc.) |
| Product | Software name |
| Version | Software version |

!!! tip "Version Detection"
    For accurate version detection, run **Normal** or **Intensive** scans. Quick scans don't detect service versions.

### Security Tab

| Section | Description |
|---------|-------------|
| :material-text-box: **Threat Summary** | Human-readable risk assessment |
| :material-format-list-bulleted: **Risk Details** | Breakdown of contributing factors |
| :material-lightbulb: **Recommendations** | Actionable remediation steps |
| :material-bug: **CVEs** | Known vulnerabilities (if CVE integration enabled) |

??? example "Sample Threat Summary"
    > This device has **High** risk due to exposed SMB service (port 445) and outdated SSH version. SMB is a common target for ransomware. Consider blocking external access and updating the SSH server.

### Settings Tab

| Field | Description |
|-------|-------------|
| :material-tag: **Label** | Friendly name (e.g., `proxmox-01`) |
| :material-folder: **Zone** | Network segment |
| :material-shield-check: **Trusted** | Mark as known/expected |
| :material-note-text: **Notes** | Free-form notes |

---

## Zones

Organize devices by function for easier management.

### Suggested Zones

| Zone | Purpose | Examples |
|------|---------|----------|
| :material-server: **Servers** | Infrastructure | NAS, hypervisors, Docker hosts |
| :material-router-wireless: **Network** | Network equipment | Routers, switches, APs, firewalls |
| :material-desktop-tower: **Workstations** | User devices | Desktops, laptops |
| :material-lightbulb: **IoT** | Smart devices | Cameras, thermostats, sensors |
| :material-earth: **DMZ** | Exposed services | Web servers, VPN endpoints |
| :material-cog: **Management** | Admin interfaces | IPMI, iLO, iDRAC |
| :material-database: **Storage** | Storage devices | SAN, backup targets |

!!! info "Custom Zones"
    Create your own zones in **Settings** :octicons-arrow-right-16: **Zones**. Zone names are freeform.

---

## Best Practices

!!! tip "Device Organization Workflow"

    1. **After first scan**: Label all known devices
    2. **Assign zones**: Group by function
    3. **Mark trusted**: Reduce alert noise
    4. **Add notes**: Document purpose, owner, etc.
    5. **Regular review**: Check for unknown devices
