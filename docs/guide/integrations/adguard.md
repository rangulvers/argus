# AdGuard Home

Enrich devices with DNS query data from AdGuard Home.

## Features

- :material-dns: DNS queries per device (24h)
- :material-cancel: Blocked queries and block rate
- :material-format-list-bulleted: Top queried domains
- :material-alert: Suspicious domain detection
- :material-gauge: DNS behavior risk scoring

## Configuration

| Field | Description | Example |
|-------|-------------|---------|
| **AdGuard URL** | URL to your AdGuard Home | `http://192.168.1.2:3000` |
| **Username** | Admin username | `admin` |
| **Password** | Admin password | `your-password` |
| **Verify SSL** | Validate SSL certificate | Enable for HTTPS |
| **Sync on Scan** | Auto-fetch during scans | Recommended |

!!! note "Default Port"
    AdGuard Home's web interface runs on port **3000** by default. Don't forget to include it in the URL.

## Authentication

AdGuard Home uses username/password authentication:

```yaml
username: admin
password: your-secure-password
```

!!! warning "Security Consideration"
    Consider creating a dedicated read-only account for Argus if your AdGuard Home version supports it.

## What You'll See

On the device detail page, a new **DNS Activity** section shows:

| Metric | Description |
|--------|-------------|
| **Total Queries** | DNS queries in last 24 hours |
| **Blocked Count** | Number of blocked queries |
| **Block Percentage** | Ratio of blocked to total |
| **DNS Risk Score** | Calculated risk (0-100) |
| **Top Domains** | 10 most queried domains |
| **Blocked Domains** | List of blocked queries |
| **Suspicious Domains** | Flagged suspicious activity |

## DNS Risk Scoring

Same as Pi-hole, Argus calculates a DNS Risk Score based on device behavior:

| Factor | Impact |
|--------|--------|
| High blocked percentage (>50%) | +30 points |
| Suspicious domains detected | +10 points each |
| Very high query volume | +10 points |
| Known malware domains | +20 points |

## AdGuard vs Pi-hole

Both integrations provide similar functionality. Choose based on your setup:

| Feature | Pi-hole | AdGuard Home |
|---------|---------|--------------|
| **Protocol** | DNS | DNS, DoH, DoT |
| **Interface** | Web | Web + App |
| **DHCP** | Optional | Built-in |
| **Filtering** | Blocklists | Blocklists + Parental |
| **Argus Data** | Identical | Identical |

!!! tip "Use One or Both"
    You can enable both integrations if you run multiple DNS servers on your network.

## Setup Checklist

- [x] AdGuard Home running and accessible
- [ ] Note the AdGuard Home URL (including port 3000)
- [ ] Have admin credentials ready
- [ ] Configure integration in Argus Settings
- [ ] Test connection
- [ ] Enable Sync on Scan

??? question "Troubleshooting: Connection Failed"

    **Connection refused**

    - Verify AdGuard Home is running
    - Check URL includes port 3000 (or your custom port)
    - Ensure no firewall blocking the connection

    **Authentication failed**

    - Verify username and password are correct
    - Try logging into AdGuard Home web UI with same credentials
    - Check for typos in configuration

??? question "Troubleshooting: No Data for Devices"

    **Empty DNS data**

    - Devices must use AdGuard Home as their DNS server
    - Check AdGuard Home shows queries from the device IP
    - DNS data is from last 24 hours only

    **Query log disabled**

    - Ensure query logging is enabled in AdGuard Home
    - Settings :octicons-arrow-right-16: General Settings :octicons-arrow-right-16: Query Log
