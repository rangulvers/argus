# Argus - Home Network Security Monitor

<p align="center">
  <img src="assets/logo.png" alt="Argus Logo" width="200">
</p>

<p align="center">
  <strong>Keep your home network safe.</strong>
</p>

<p align="center">
  <a href="https://github.com/rangulvers/argus"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python"></a>
  <a href="https://github.com/rangulvers/argus/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
  <a href="https://ghcr.io/rangulvers/argus"><img src="https://img.shields.io/badge/docker-ready-blue.svg" alt="Docker"></a>
</p>

---

Argus automatically discovers all devices on your network, monitors for changes, and alerts you to potential security threats.

## Why Argus?

Your home network is growing. Smart TVs, IoT devices, phones, computers - it's hard to keep track of what's connected. Argus gives you visibility and control:

<div class="grid cards" markdown>

-   :material-radar:{ .lg .middle } __Know What's Connected__

    ---

    See every device on your network with detailed information including IP, MAC, vendor, and OS.

-   :material-shield-alert:{ .lg .middle } __Spot Intruders__

    ---

    Get alerts when new devices appear on your network that you don't recognize.

-   :material-bug:{ .lg .middle } __Find Vulnerabilities__

    ---

    Identify risky open ports and known CVEs that could expose your network.

-   :material-history:{ .lg .middle } __Track Changes__

    ---

    Monitor your network over time with scan history and change detection.

</div>

## Quick Start

Get Argus running in under a minute:

=== "Docker (Recommended)"

    ```bash
    # Create directory and download files
    mkdir argus && cd argus
    curl -O https://raw.githubusercontent.com/rangulvers/argus/main/docker-compose.yml
    curl -o config.yaml https://raw.githubusercontent.com/rangulvers/argus/main/config.yaml.example

    # Edit config.yaml - set your network
    nano config.yaml

    # Start Argus
    docker compose up -d
    ```

=== "Docker Run"

    ```bash
    docker run -d \
      --name argus \
      --network host \
      --cap-add NET_ADMIN \
      --cap-add NET_RAW \
      -v ./data:/app/data \
      -v ./config.yaml:/app/config.yaml:ro \
      ghcr.io/rangulvers/argus:latest
    ```

Access the web UI at **[http://localhost:8080](http://localhost:8080)**

On first visit, you'll be prompted to create an admin account.

## Features

### Network Discovery
- Automatic device detection using nmap
- MAC address, hostname, and vendor identification
- OS fingerprinting to identify device types
- Multiple scan profiles (quick, normal, intensive)

### Security Analysis
- Risk scoring based on open ports and services
- CVE vulnerability matching for common services
- Threat severity classification (Critical, High, Medium, Low)
- Actionable remediation recommendations

### Device Management
- Custom labels and notes for devices
- Mark devices as trusted to reduce noise
- Organize devices by zones (IoT, Servers, Workstations)
- Persistent tracking across scans via MAC address

### Modern Interface
- Clean, responsive web dashboard
- Dark mode support
- Real-time scan progress
- Historical trend charts

## Screenshots

!!! info "Coming Soon"
    Screenshots will be added in a future update.

## Getting Help

- :material-book: [Documentation](getting-started/installation.md) - Full setup and usage guide
- :material-github: [GitHub Issues](https://github.com/rangulvers/argus/issues) - Report bugs or request features
- :material-api: [API Reference](api/overview.md) - Integrate with your own tools

## License

Argus is open source software licensed under the [MIT License](https://github.com/rangulvers/argus/blob/main/LICENSE).

---

<p align="center">
  Built with :material-heart: for the homelab community
</p>
