# UniFi Network

Enrich devices with connection data from UniFi Controller (UDM, Cloud Key, or self-hosted).

## Features

- :material-wifi: Wireless connection info (SSID, signal strength, channel)
- :material-chart-line: Traffic statistics (upload/download)
- :material-ethernet: Switch port mapping
- :material-check-network: Client online/offline status

## Configuration

| Field | Description | Example |
|-------|-------------|---------|
| **Controller URL** | URL to your UniFi controller | `https://192.168.1.1` |
| **Controller Type** | UDM, Self-Hosted, or Cloud | `UDM` |
| **Site ID** | Site name in UniFi | `default` |
| **Authentication** | Username/Password or API Key | See below |
| **Verify SSL** | Validate SSL certificate | Enable for valid certs |
| **Sync on Scan** | Auto-fetch during scans | Recommended |

!!! note "Controller URL Examples"
    - **UDM/UDM Pro**: `https://192.168.1.1`
    - **Cloud Key**: `https://192.168.1.2:8443`
    - **UniFi Cloud**: `https://unifi.ui.com`

## Authentication Methods

=== "Username & Password"

    Use a local admin account on your UniFi controller.

    ```yaml
    username: argus-reader
    password: your-secure-password
    ```

    !!! warning "Security Consideration"
        Create a dedicated read-only account for Argus rather than using your main admin credentials.

=== "API Key"

    Create a read-only API key in **UniFi Settings** :octicons-arrow-right-16: **Admins** :octicons-arrow-right-16: **API Keys**.

    ```yaml
    api_key: your-unifi-api-key
    ```

    !!! tip "Recommended"
        API keys are more secure as they don't expose admin credentials and can be easily revoked.

## Data Retrieved

Once configured, Argus retrieves the following data for each device:

| Data | Description |
|------|-------------|
| **WiFi SSID** | Network name device is connected to |
| **Signal Strength** | dBm signal level and quality |
| **Channel** | WiFi channel (2.4GHz or 5GHz) |
| **Upload/Download** | Traffic statistics in bytes |
| **Switch Port** | Physical port if wired |
| **Experience Score** | UniFi's connection quality score |

## Setup Checklist

- [x] UniFi Controller accessible from Argus host
- [ ] Create read-only user or API key
- [ ] Note your Site ID (usually `default`)
- [ ] Configure integration in Argus Settings
- [ ] Test connection
- [ ] Enable Sync on Scan

??? question "Troubleshooting: Connection Failed"

    **Certificate errors**

    If using self-signed certificates, disable "Verify SSL" in the integration settings.

    **Authentication failed**

    - Verify username/password or API key is correct
    - Ensure the account has read access to the site
    - For UDM, try both local and UI.com accounts

    **Network unreachable**

    - Check that Argus can reach the controller URL
    - Verify firewall rules allow the connection
    - For Docker, ensure proper network mode

??? question "Troubleshooting: No Data Returned"

    **Empty device list**

    - Verify the Site ID is correct
    - Check that devices are active on the controller
    - Ensure the account has permission to view clients

    **Missing WiFi data**

    - WiFi data only available for wireless clients
    - Wired devices show switch port info instead
