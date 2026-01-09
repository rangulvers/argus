# Installation

## Requirements

- Docker 20.10+ (recommended) or Python 3.11+
- nmap 7.80+

## Docker (Recommended)

### Docker Compose

```bash
mkdir argus && cd argus

# Get config
curl -o config.yaml https://raw.githubusercontent.com/rangulvers/argus/main/config.yaml.example

# Edit subnet
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

!!! note "Network Mode"
    `--network host` is required for accurate L2/L3 discovery.

## Manual Installation

```bash
# Install nmap
sudo apt-get install nmap  # Debian/Ubuntu
brew install nmap          # macOS
sudo dnf install nmap      # Fedora

# Clone and setup
git clone https://github.com/rangulvers/argus.git
cd argus
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure
cp config.yaml.example config.yaml
nano config.yaml

# Run (sudo for full nmap features)
sudo .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## Updating

```bash
# Docker
docker compose pull && docker compose up -d

# Manual
git pull && pip install -r requirements.txt
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Permission denied | Run with `sudo` or use Docker |
| No devices found | Check subnet in `config.yaml`, verify network interface |
| Container won't start | Ensure `--network host` and caps are set |

## Next Steps

- [Configuration](configuration.md)
- [First Scan](first-scan.md)
