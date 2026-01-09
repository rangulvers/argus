# Installation

This guide covers the different ways to install and run Argus.

## Requirements

- **Python**: 3.11 or higher (for manual installation)
- **nmap**: 7.80 or higher
- **Docker**: 20.10+ (for containerized deployment)

## Docker Installation (Recommended)

Docker is the easiest way to get started with Argus.

### Using Docker Compose

1. **Create a directory for Argus**:

    ```bash
    mkdir argus && cd argus
    ```

2. **Download the required files**:

    ```bash
    curl -O https://raw.githubusercontent.com/rangulvers/argus/main/docker-compose.yml
    curl -o config.yaml https://raw.githubusercontent.com/rangulvers/argus/main/config.yaml.example
    ```

3. **Configure your network**:

    Edit `config.yaml` and set your network subnet:

    ```yaml
    network:
      subnet: "192.168.1.0/24"  # Change to your network
    ```

4. **Start Argus**:

    ```bash
    docker compose up -d
    ```

5. **Access the web UI** at [http://localhost:8080](http://localhost:8080)

### Using Docker Run

If you prefer not to use Docker Compose:

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

!!! warning "Network Mode"
    Argus requires `--network host` for accurate network discovery. This gives the container full access to the host's network stack.

### Docker Capabilities

Argus needs these Linux capabilities for nmap to function properly:

| Capability | Purpose |
|------------|---------|
| `NET_ADMIN` | Required for network interface operations |
| `NET_RAW` | Required for raw packet operations (ping, SYN scans) |

## Manual Installation

For development or when Docker isn't available.

### 1. Install nmap

=== "Debian/Ubuntu"

    ```bash
    sudo apt-get update
    sudo apt-get install nmap
    ```

=== "macOS"

    ```bash
    brew install nmap
    ```

=== "Fedora/RHEL"

    ```bash
    sudo dnf install nmap
    ```

=== "Arch Linux"

    ```bash
    sudo pacman -S nmap
    ```

### 2. Clone the Repository

```bash
git clone https://github.com/rangulvers/argus.git
cd argus
```

### 3. Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate     # Windows
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure Argus

```bash
cp config.yaml.example config.yaml
nano config.yaml  # Edit with your network settings
```

### 6. Start the Server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

!!! tip "Running with sudo"
    For full nmap functionality (OS detection, SYN scans), run with elevated privileges:
    ```bash
    sudo .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
    ```

## Verifying Installation

1. Open [http://localhost:8080](http://localhost:8080) in your browser
2. You should see the setup page to create an admin account
3. After creating your account, you'll be redirected to the dashboard
4. Click "Run Scan" to verify nmap is working

## Updating Argus

### Docker

```bash
docker compose pull
docker compose up -d
```

### Manual Installation

```bash
cd argus
git pull
pip install -r requirements.txt
# Restart the server
```

## Troubleshooting

### "Permission denied" errors

Nmap requires elevated privileges for certain scan types. Either:

- Run with `sudo`
- Use Docker (recommended)
- Configure Linux capabilities: `sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)`

### "No devices found"

1. Check your subnet configuration in `config.yaml`
2. Verify your network interface is correct
3. Try running a quick scan first
4. Check firewall rules aren't blocking nmap

### Docker container won't start

1. Ensure `--network host` is set
2. Verify capabilities are granted
3. Check logs: `docker logs argus`

## Next Steps

- [Configure Argus](configuration.md) for your network
- [Run your first scan](first-scan.md)
