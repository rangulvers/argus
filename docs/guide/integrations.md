# Integrations

Extend Argus by connecting external services to enrich device data and enhance security insights.

![Integrations Overview](../assets/argus_integrations.png)

## Available Integrations

| Integration | Description | Data Provided |
|-------------|-------------|---------------|
| **UniFi Network** | Ubiquiti network controller | WiFi info, traffic stats, switch ports |
| **Pi-hole** | DNS sinkhole | DNS queries, blocked domains, top domains |
| **AdGuard Home** | DNS server | DNS queries, blocked domains, query stats |
| **CVE Database** | NVD vulnerability data | CVE matches, severity scores, remediation |

## Accessing Integrations

Navigate to **Settings** → **External Integrations** → **Manage Integrations** to view and configure all available integrations.

---

## UniFi Network

Enrich devices with connection data from UniFi Controller (UDM, Cloud Key, or self-hosted).

### Features

- Wireless connection info (SSID, signal strength, channel)
- Traffic statistics (upload/download)
- Switch port mapping
- Client online/offline status

### Configuration

| Field | Description |
|-------|-------------|
| Controller URL | `https://192.168.1.1` or `https://unifi.ui.com` |
| Controller Type | UDM, Self-Hosted, or Cloud |
| Site ID | Usually `default` |
| Authentication | Username/Password or API Key |
| Verify SSL | Enable for valid certificates |
| Sync on Scan | Auto-fetch data during scans |

### Authentication Methods

=== "Username & Password"

    Use a local admin account on your UniFi controller.

=== "API Key"

    Create a read-only API key in **UniFi Settings** → **Admins** → **API Keys**.
    More secure as it doesn't expose admin credentials.

---

## Pi-hole

Enrich devices with DNS query data from Pi-hole (supports v5 and v6).

### Features

- DNS queries per device (24h)
- Blocked queries and block rate
- Top queried domains
- Suspicious domain detection
- DNS behavior risk scoring

### Configuration

| Field | Description |
|-------|-------------|
| Pi-hole URL | `http://pi.hole` or `http://192.168.1.2` |
| API Token | Optional for authenticated access |
| Verify SSL | Enable for HTTPS with valid cert |
| Sync on Scan | Auto-fetch data during scans |

### API Token

=== "Pi-hole v5"

    Find in **Settings** → **API** → **Show API token**

=== "Pi-hole v6"

    Create an app password in **Settings** → **Privacy**

### What You'll See

On the device detail page, a new **DNS Activity** section shows:

- Total queries (24h) and blocked count
- Block percentage and DNS risk score
- Top 10 queried domains
- Blocked domains list
- Suspicious domain warnings

---

## AdGuard Home

Enrich devices with DNS query data from AdGuard Home.

### Features

- DNS queries per device (24h)
- Blocked queries and block rate
- Top queried domains
- Suspicious domain detection
- DNS behavior risk scoring

### Configuration

| Field | Description |
|-------|-------------|
| AdGuard URL | `http://192.168.1.2:3000` |
| Username | Admin username |
| Password | Admin password |
| Verify SSL | Enable for HTTPS with valid cert |
| Sync on Scan | Auto-fetch data during scans |

!!! note "Default Port"
    AdGuard Home's web interface runs on port **3000** by default.

---

## CVE Database

Match detected services against known vulnerabilities from the National Vulnerability Database (NVD).

### Features

- CVE matching for detected services
- CVSS severity scores
- Vulnerability descriptions
- Links to detailed CVE information
- Affected version range detection

### Configuration

| Field | Description |
|-------|-------------|
| NVD API Key | Optional - increases rate limits |
| Minimum Severity | LOW, MEDIUM, HIGH, or CRITICAL |
| Cache Duration | How long to cache CVE data (1-168 hours) |
| Check on Scan | Auto-check CVEs during scans |

### NVD API Key

Get a free API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key) for:

- Higher rate limits (50 vs 5 requests per 30s)
- Faster vulnerability lookups
- More reliable service

!!! tip "Scan Profiles"
    CVE matching requires accurate service version detection. Use **Normal** or **Intensive** scan profiles for best results.

---

## DNS Risk Scoring

Both Pi-hole and AdGuard integrations calculate a **DNS Risk Score** (0-100) based on:

| Factor | Impact |
|--------|--------|
| High blocked percentage (>50%) | +30 points |
| Suspicious domains detected | +10 points each |
| Very high query volume | +10 points |
| Known malware domains | +20 points |

### Suspicious Domain Detection

Argus flags domains that match patterns commonly used by malware:

- Random-looking subdomains (high entropy)
- Known malicious TLDs
- Cryptocurrency mining pools
- Command & control patterns

---

## Integration Status

View the status of all integrations at a glance on the **Settings** → **Integrations** page:

- **Active** - Integration enabled and configured
- **Inactive** - Integration disabled

Each integration card shows the current status and provides quick access to configuration.
