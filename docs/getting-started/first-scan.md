# First Scan

Ready to scan your network? Follow this guide to run your first scan and understand the results.

## Quick Start Checklist

- [x] Argus installed and running
- [x] `config.yaml` configured with your subnet
- [ ] Create admin account
- [ ] Run first scan
- [ ] Review discovered devices
- [ ] Organize devices (labels, zones, trusted)

---

## Running a Scan

=== "Web UI"

    1. Open `http://localhost:8080`
    2. Create admin account on first visit
    3. Click **Run Scan** in the top-right
    4. Select scan profile
    5. Monitor progress in real-time

    !!! tip "First Time?"
        Start with a **Quick** scan to verify everything works, then run **Normal** for full results.

=== "CLI"

    ```bash
    # Quick scan (ping only, ~30 seconds)
    python scan_cli.py scan --profile quick

    # Normal scan (ports + services, 3-5 minutes)
    python scan_cli.py scan --profile normal --detect-changes

    # Specific subnet
    python scan_cli.py scan --subnet 10.0.0.0/24
    ```

    Press ++ctrl+c++ to cancel a running scan.

=== "API"

    ```bash
    # Trigger scan
    curl -X POST "http://localhost:8080/api/scan/trigger?profile=quick"

    # Check status
    curl http://localhost:8080/api/scan/status
    ```

---

## Scan Profiles

| Profile | What it Does | Time (50 hosts) | Best For |
|---------|--------------|-----------------|----------|
| :material-flash: **Quick** | Ping sweep only | ~30 seconds | Device presence check |
| :material-shield-search: **Normal** | Ports 1-1000 + services | 3-5 minutes | Regular security audits |
| :material-magnify: **Intensive** | All ports + scripts | 15-30 minutes | Deep analysis |

!!! info "Recommended Approach"
    1. Run **Quick** first to verify connectivity
    2. Run **Normal** to establish a security baseline
    3. Use **Intensive** sparingly for detailed analysis

---

## Understanding Results

### Risk Levels

| Level | Color | Meaning | Example |
|-------|-------|---------|---------|
| :material-alert-octagon:{ .text-red } **Critical** | Red | Immediate action needed | Telnet exposed |
| :material-alert:{ .text-orange } **High** | Orange | Significant risk | SMB, RDP open |
| :material-alert-outline:{ .text-yellow } **Medium** | Yellow | Moderate concern | Uncommon services |
| :material-information:{ .text-blue } **Low** | Blue | Minor issue | Info disclosure |
| :material-check-circle:{ .text-green } **None** | Green | No detected issues | Clean device |

### Risky Ports

!!! danger "Critical Risk Ports"
    These services should almost never be exposed on a home network:

    | Port | Service | Risk |
    |------|---------|------|
    | 23 | Telnet | Cleartext credentials |
    | 21 | FTP | Cleartext authentication |
    | 445 | SMB | Common ransomware target |
    | 3389 | RDP | Brute force attacks |
    | 5900 | VNC | Often weak authentication |

??? info "Other Ports of Interest"

    | Port | Service | Notes |
    |------|---------|-------|
    | 22 | SSH | OK if properly secured |
    | 80/443 | HTTP/HTTPS | Check what's being served |
    | 8080 | Alt HTTP | Often admin interfaces |
    | 1883 | MQTT | IoT protocol, often unsecured |
    | 5353 | mDNS | Service discovery |

---

## Device Organization

Organize your devices for easier management and cleaner dashboards.

### Zones

Group devices by function:

| Zone | Purpose | Examples |
|------|---------|----------|
| :material-server: **Servers** | Infrastructure | NAS, Docker hosts, VMs |
| :material-router-wireless: **Network** | Network gear | Routers, switches, APs |
| :material-desktop-tower: **Workstations** | User devices | Desktops, laptops |
| :material-lightbulb: **IoT** | Smart devices | Cameras, thermostats |
| :material-earth: **DMZ** | Exposed services | Web servers |

### Labels

Add descriptive names for quick identification:

```
proxmox-01
unifi-ap-garage
synology-nas
ring-doorbell
```

### Trusted Devices

!!! tip "Reduce Noise"
    Mark known devices as **trusted** to filter them from security alerts. Trusted devices still appear in scans but won't trigger new device alerts.

---

## Scheduled Scans

Automate regular scanning to catch changes.

=== "Cron (Manual Install)"

    ```bash
    # Quick scan every 6 hours
    0 */6 * * * cd /path/to/argus && python scan_cli.py scan --profile quick --detect-changes

    # Normal scan nightly at 2 AM
    0 2 * * * cd /path/to/argus && python scan_cli.py scan --profile normal --detect-changes
    ```

=== "Docker Environment"

    ```yaml title="docker-compose.yml"
    environment:
      - SCAN_SCHEDULE=0 2 * * *
    ```

!!! warning "Intensive Scans"
    Don't schedule intensive scans frequently. They generate significant network traffic and can take 30+ minutes on larger networks.

---

## What's Next?

<div class="grid cards" markdown>

-   :material-view-dashboard: **Dashboard**

    ---

    Learn to navigate the dashboard and understand metrics

    [:octicons-arrow-right-24: Dashboard Guide](../guide/dashboard.md)

-   :material-api: **API Reference**

    ---

    Automate Argus with the REST API

    [:octicons-arrow-right-24: API Docs](../api/endpoints.md)

-   :material-connection: **Integrations**

    ---

    Connect UniFi, Pi-hole, AdGuard, and more

    [:octicons-arrow-right-24: Set Up Integrations](../guide/integrations/index.md)

</div>
