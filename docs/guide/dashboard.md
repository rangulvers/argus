# Dashboard

The dashboard provides an at-a-glance overview of your network's security status.

## Overview Cards

The top of the dashboard shows key metrics:

### Total Devices

The total number of unique devices ever discovered on your network. This count persists across scans.

### Devices at Risk

Devices with a risk level of Medium, High, or Critical. Click to filter the device list.

### Critical / High Risk

Specific counts of devices needing immediate attention.

### Last Scan

When the most recent scan was completed.

## Historical Trend Charts

Four interactive charts show network metrics over time:

### Device Count

Track how many devices are on your network over time. Useful for:

- Identifying when new devices joined
- Spotting patterns (more devices on weekends?)
- Detecting device churn

### Average Risk Score

The average risk score across all devices. Trending up? Time to investigate.

### Open Ports

Total open ports discovered. A sudden spike might indicate:

- New services started
- Security misconfiguration
- Potential compromise

### Network Changes

Number of changes detected per scan:

- New devices
- Removed devices
- Port changes
- Service changes

### Time Range Selection

Use the dropdown to adjust the chart time range:

- **7 days** - Recent activity
- **30 days** - Monthly trends (default)
- **90 days** - Quarterly view
- **1 year** - Long-term patterns

## Latest Scan Summary

Shows details of the most recent scan:

| Field | Description |
|-------|-------------|
| Status | Completed, Running, or Failed |
| Subnet | Network range that was scanned |
| Devices Found | Number of devices discovered |

## Device Table

A quick view of devices from the latest scan, showing:

- Risk level indicator
- IP address
- Hostname
- Vendor
- Open port count

Click any row to view full device details.

## Recent Changes

The most recent network changes detected:

| Change Type | Description |
|-------------|-------------|
| Device Added | New device appeared |
| Device Removed | Device no longer responding |
| Port Opened | New port accessible |
| Port Closed | Port no longer accessible |
| Service Changed | Service version or type changed |

Click "View all changes" to see the full change history.

## Dashboard Actions

### Run Scan

Click the "Run Scan" button to start a new scan. Choose from:

- **Quick Scan** - Fast device discovery
- **Normal Scan** - Standard security scan
- **Intensive Scan** - Deep analysis

### Dark Mode

Toggle between light and dark themes using the sun/moon icon.

## Tips

!!! tip "Regular Monitoring"
    Check the dashboard daily, especially the "Recent Changes" section. New devices or ports should always be investigated.

!!! tip "Trend Analysis"
    Use the historical charts to establish a baseline for your network. Deviations from normal patterns warrant investigation.

!!! tip "Risk Scores"
    A rising average risk score across your network might indicate:

    - New vulnerable devices added
    - Services misconfigured
    - Need for security updates
