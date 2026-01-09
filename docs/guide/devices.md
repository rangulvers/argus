# Devices

The Devices page shows all devices discovered on your network with powerful filtering and management tools.

## Device List

### Columns

| Column | Description |
|--------|-------------|
| Risk | Security risk level (Critical, High, Medium, Low, None) |
| IP Address | Device's network address |
| Hostname | Device name from DNS/NetBIOS |
| Label | Your custom name for the device |
| Vendor | Manufacturer based on MAC address |
| Zone | Network zone you've assigned |
| Ports | Number of open ports |
| Actions | Quick actions and view link |

### Row Colors

- **Red background** - Critical risk device
- **Orange background** - High risk device
- **Green shield icon** - Trusted device

## Filtering Devices

Use the filters at the top to find specific devices:

### Search

Search across:

- IP address
- Hostname
- MAC address
- Vendor name
- Label

### Risk Level Filter

Filter by security risk:

- All Risks
- Critical
- High
- Medium
- Low
- None

### Trusted Filter

- All Devices
- Trusted Only
- Untrusted Only

### Zone Filter

Filter by network zone (shows zones you've created).

### Port Filter

Search for devices with specific open ports:

```
22          # Devices with SSH
80,443      # Devices with web servers
3389        # Devices with RDP
```

### Open Ports Filter

- All Devices
- Has Open Ports
- No Open Ports

## Quick Actions Menu

Click the three-dot menu (⋮) on any device row for quick actions:

### Copy IP Address

Copy the device's IP to your clipboard.

### Copy MAC Address

Copy the device's MAC address to your clipboard.

### Scan This Device

Run an immediate scan on just this device.

### Mark as Trusted / Untrusted

Toggle the device's trusted status.

### View Details

Open the full device details page.

## Device Details Page

Click on any device to see full details:

### Device Information

- IP Address
- MAC Address
- Hostname
- Vendor
- Operating System (if detected)
- First Seen / Last Seen
- Risk Score and Level

### Open Ports

List of all open ports with:

| Field | Description |
|-------|-------------|
| Port | Port number and protocol |
| State | Open, Filtered, etc. |
| Service | Service name (SSH, HTTP, etc.) |
| Product | Software name |
| Version | Software version |

### Security Analysis

#### Threat Summary

A human-readable summary of security concerns.

#### Risk Details

Breakdown of risk factors:

- Risky ports detected
- Vulnerable services
- CVE vulnerabilities

#### Recommendations

Actionable steps to improve security:

- "Disable Telnet and use SSH instead"
- "Update SSH to latest version"
- "Restrict SMB access to trusted IPs"

### CVE Vulnerabilities

Known vulnerabilities affecting the device's services:

| Field | Description |
|-------|-------------|
| CVE ID | Unique vulnerability identifier |
| Severity | Critical, High, Medium, Low |
| Description | What the vulnerability allows |
| Link | NVD reference |

### Device Settings

Edit device properties:

#### Label

Give the device a friendly name (e.g., "Living Room TV").

#### Zone

Assign to a network zone for organization:

- Start typing to see existing zones
- Or create a new zone by typing a new name

Common zones:

- `Workstations`
- `Servers`
- `IoT`
- `Mobile`
- `Network`
- `Guest`

#### Trusted

Mark device as trusted to:

- Indicate it's a known, expected device
- Reduce alert noise
- Filter in device list

#### Notes

Add private notes about the device:

- Configuration details
- Owner information
- Known issues
- Maintenance history

## Best Practices

!!! tip "Label Everything"
    Take time to label all your devices after the first scan. This makes it much easier to spot unknown devices later.

!!! tip "Use Zones"
    Organize devices into zones to:

    - Quickly filter the device list
    - Identify misplaced devices
    - Apply different security policies

!!! tip "Review Regularly"
    Periodically review:

    - Devices without labels (new or forgotten)
    - High-risk devices
    - Devices with many open ports

!!! warning "Unknown Devices"
    Any device you don't recognize should be investigated:

    1. Check the MAC vendor - does it match expected manufacturers?
    2. Look at the hostname - any clues?
    3. Check open ports - what services is it running?
    4. If still unknown, consider blocking it at your router
