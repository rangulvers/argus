# Installation

## Requirements

- Docker 20.10+ (recommended) or Python 3.11+
- nmap 7.80+

## Docker (Recommended)

!!! tip "Why Docker?"
    Docker is the easiest way to run Argus. It handles all dependencies and provides multi-arch support (amd64, arm64, armv7) for Raspberry Pi and other ARM devices.

### Docker Compose

```bash
mkdir argus && cd argus

# Get config
curl -o config.yaml https://raw.githubusercontent.com/rangulvers/argus/main/config.yaml.example

# Edit subnet - set your network (e.g., 192.168.1.0/24)
nano config.yaml
```

```yaml title="docker-compose.yml"
services:
  argus:
    image: ghcr.io/rangulvers/argus:latest
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./data:/app/data
      - ./config.yaml:/app/config.yaml:ro
    restart: unless-stopped
```

```bash
docker compose up -d
```

Web UI: `http://localhost:8080`

### Docker Run

```bash
docker run -d \
  --name argus \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  ghcr.io/rangulvers/argus:latest
```

!!! warning "Network Mode Required"
    `--network host` is required for accurate L2/L3 discovery. Bridge networking will not work correctly for network scanning.

### Setup Checklist

- [x] Docker installed
- [ ] Create directory and download config
- [ ] Edit `config.yaml` with your subnet
- [ ] Create `docker-compose.yml`
- [ ] Run `docker compose up -d`
- [ ] Access web UI at `http://localhost:8080`

---

## Manual Installation

For users who prefer to run without Docker.

=== "Debian/Ubuntu"

    ```bash
    sudo apt-get update
    sudo apt-get install nmap python3 python3-venv
    ```

=== "macOS"

    ```bash
    brew install nmap python@3.11
    ```

=== "Fedora/RHEL"

    ```bash
    sudo dnf install nmap python3 python3-pip
    ```

### Clone and Setup

```bash
# Clone repository
git clone https://github.com/rangulvers/argus.git
cd argus

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure
cp config.yaml.example config.yaml
nano config.yaml
```

### Run the Server

```bash
# Run with sudo for full nmap features
sudo .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
```

!!! info "Why sudo?"
    nmap requires elevated privileges for OS detection, service version detection, and raw packet operations. Without sudo, some scan features will be limited.

### Setup Checklist

- [x] Python 3.11+ installed
- [x] nmap installed
- [ ] Clone repository
- [ ] Create virtual environment
- [ ] Install dependencies
- [ ] Configure `config.yaml`
- [ ] Run server with sudo

---

## Updating

=== "Docker"

    ```bash
    docker compose pull
    docker compose up -d
    ```

=== "Manual"

    ```bash
    git pull
    pip install -r requirements.txt
    ```

---

## Troubleshooting

??? question "Permission denied errors"

    **Docker**: Ensure you have the required capabilities:
    ```bash
    docker run --cap-add NET_ADMIN --cap-add NET_RAW ...
    ```

    **Manual**: Run with `sudo`:
    ```bash
    sudo .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
    ```

??? question "No devices found"

    1. **Check your subnet** in `config.yaml`:
       ```yaml
       network:
         subnet: "192.168.1.0/24"  # Your actual network
       ```

    2. **Verify network interface** - Docker must use host networking:
       ```bash
       docker run --network host ...
       ```

    3. **Test nmap directly**:
       ```bash
       sudo nmap -sn 192.168.1.0/24
       ```

??? question "Container won't start"

    **Check logs**:
    ```bash
    docker logs argus
    ```

    **Common issues**:

    - Missing `--network host` flag
    - Missing capabilities (`NET_ADMIN`, `NET_RAW`)
    - Invalid `config.yaml` syntax
    - Port 8080 already in use

??? question "Database errors"

    **Reset database**:
    ```bash
    # Stop Argus
    docker compose down

    # Remove database
    rm -f data/argus.db

    # Restart
    docker compose up -d
    ```

---

## Next Steps

<div class="grid cards" markdown>

-   :material-cog: **Configuration**

    ---

    Customize scan profiles, alerts, and integrations

    [:octicons-arrow-right-24: Configure Argus](configuration.md)

-   :material-radar: **First Scan**

    ---

    Run your first network scan and explore results

    [:octicons-arrow-right-24: Start Scanning](first-scan.md)

</div>
