# Security Migration Guide: v1.x → v2.0

## Overview

Argus v2.0 introduces **critical security improvements** that change how sensitive information (passwords, API keys, tokens) is stored. This is a **breaking change** that requires manual migration.

**Key Changes:**
- Secrets must now be stored as **environment variables** (not in `config.yaml`)
- Session secrets must be explicitly configured for production
- Improved protection against command injection and DoS attacks
- Optimized API key authentication performance

---

## Migration Checklist

- [ ] Run the automated migration script
- [ ] Generate a secure session secret
- [ ] Update `.env` file with all required secrets
- [ ] Update your deployment configuration (Docker/systemd)
- [ ] Test the migration in a non-production environment first
- [ ] Update backup and disaster recovery procedures
- [ ] Review the changelog for other breaking changes

---

## Automated Migration (Recommended)

### Step 1: Backup Your Configuration

```bash
# Create a backup of your current configuration
cp config.yaml config.yaml.backup
cp .env .env.backup 2>/dev/null || true
```

### Step 2: Run the Migration Script

```bash
# Navigate to your Argus installation directory
cd /path/to/argus

# Run the migration script (dry-run first)
python migrate_secrets.py --dry-run

# If the dry-run looks good, run the actual migration
python migrate_secrets.py
```

The script will:
1. Extract secrets from `config.yaml`
2. Create/update `.env` file with proper formatting
3. Backup `config.yaml` (timestamped backup)
4. Replace secrets in `config.yaml` with `***REDACTED***`
5. Set restrictive permissions (600) on `.env`

### Step 3: Generate Session Secret

```bash
# Generate a secure random session secret
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Add the generated secret to your `.env` file:

```bash
echo "ARGUS_SESSION_SECRET=<generated_secret_here>" >> .env
```

### Step 4: Set Production Mode (Optional but Recommended)

```bash
echo "ARGUS_ENVIRONMENT=production" >> .env
```

In production mode, Argus will:
- Require `ARGUS_SESSION_SECRET` environment variable
- Refuse to start without proper secrets configuration
- Disable file-based fallback secrets

### Step 5: Restart Argus

```bash
# If using systemd
sudo systemctl restart argus

# If using Docker
docker-compose restart

# If running manually
sudo python scan_cli.py scan --subnet 192.168.1.0/24  # Test scan
uvicorn app.main:app --host 0.0.0.0 --port 8080  # Test web server
```

### Step 6: Verify Migration

```bash
# Check that secrets are redacted in config.yaml
grep -i "password\|secret\|api_key" config.yaml

# Should output lines like:
#   smtp_password: ***REDACTED***
#   secret: ***REDACTED***

# Verify .env file has correct permissions
ls -la .env
# Should show: -rw------- (600)

# Test that Argus starts without errors
curl http://localhost:8080/health
```

---

## Manual Migration (Alternative)

If you prefer manual migration or have a custom setup:

### 1. Identify Secrets in Your Configuration

Open `config.yaml` and find any of these fields:
- `email.smtp_password`
- `webhook.secret`
- `cve_integration.api_key`
- `unifi_integration.password`
- `unifi_integration.api_key`
- `pihole_integration.api_token`
- `adguard_integration.password`

### 2. Create/Update `.env` File

Create a `.env` file in the Argus root directory with the following format:

```bash
# Required: Session secret (generate with: python -c 'import secrets; print(secrets.token_urlsafe(32))')
ARGUS_SESSION_SECRET=your_secure_session_secret_here

# Optional: Only add the secrets you're actually using

# Email notifications
ARGUS_EMAIL_SMTP_PASSWORD=your_smtp_password

# Webhook notifications
ARGUS_WEBHOOK_SECRET=your_webhook_secret

# CVE integration
ARGUS_CVE_API_KEY=your_nvd_api_key

# UniFi integration
ARGUS_UNIFI_PASSWORD=your_unifi_password
ARGUS_UNIFI_API_KEY=your_unifi_api_key

# Pi-hole integration
ARGUS_PIHOLE_API_TOKEN=your_pihole_token

# AdGuard integration
ARGUS_ADGUARD_PASSWORD=your_adguard_password

# Production mode (recommended)
ARGUS_ENVIRONMENT=production
```

### 3. Set File Permissions

```bash
chmod 600 .env
```

### 4. Update `config.yaml`

Replace secret values with `***REDACTED***`:

```yaml
email:
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  smtp_username: "alerts@example.com"
  smtp_password: "***REDACTED***"  # Now loaded from ARGUS_EMAIL_SMTP_PASSWORD
```

### 5. Add `.env` to `.gitignore`

```bash
echo ".env" >> .gitignore
```

---

## Docker Deployment

### Docker Compose

Update your `docker-compose.yml`:

```yaml
version: '3.8'

services:
  argus:
    image: argus:latest
    container_name: argus
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
      - ./config.yaml:/app/config.yaml:ro
    environment:
      # Load secrets from environment file
      - ARGUS_ENVIRONMENT=production
    env_file:
      - .env  # Load all ARGUS_* variables from .env
    restart: unless-stopped
    network_mode: host  # Required for network scanning
    cap_add:
      - NET_ADMIN
      - NET_RAW
```

Create `.env` file with secrets (see above) and restart:

```bash
docker-compose down
docker-compose up -d
docker-compose logs -f
```

### Docker Secrets (Docker Swarm)

For Docker Swarm deployments, use Docker secrets:

```yaml
version: '3.8'

services:
  argus:
    image: argus:latest
    secrets:
      - argus_session_secret
      - argus_email_password
    environment:
      - ARGUS_SESSION_SECRET_FILE=/run/secrets/argus_session_secret
      - ARGUS_EMAIL_SMTP_PASSWORD_FILE=/run/secrets/argus_email_password
      - ARGUS_ENVIRONMENT=production

secrets:
  argus_session_secret:
    external: true
  argus_email_password:
    external: true
```

Create secrets:

```bash
echo "your_session_secret" | docker secret create argus_session_secret -
echo "your_email_password" | docker secret create argus_email_password -
```

---

## Kubernetes Deployment

Use Kubernetes Secrets:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: argus-secrets
type: Opaque
stringData:
  session-secret: "your_session_secret_here"
  email-password: "your_email_password_here"
  # Add other secrets as needed
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argus
spec:
  replicas: 1
  selector:
    matchLabels:
      app: argus
  template:
    metadata:
      labels:
        app: argus
    spec:
      containers:
      - name: argus
        image: argus:latest
        env:
        - name: ARGUS_SESSION_SECRET
          valueFrom:
            secretKeyRef:
              name: argus-secrets
              key: session-secret
        - name: ARGUS_EMAIL_SMTP_PASSWORD
          valueFrom:
            secretKeyRef:
              name: argus-secrets
              key: email-password
        - name: ARGUS_ENVIRONMENT
          value: "production"
        ports:
        - containerPort: 8080
```

---

## Systemd Service

Update your systemd service file (`/etc/systemd/system/argus.service`):

```ini
[Unit]
Description=Argus Network Security Monitor
After=network.target

[Service]
Type=simple
User=argus
WorkingDirectory=/opt/argus
EnvironmentFile=/opt/argus/.env  # Load secrets from .env
Environment=ARGUS_ENVIRONMENT=production
ExecStart=/opt/argus/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/argus/data

[Install]
WantedBy=multi-user.target
```

Reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart argus
sudo systemctl status argus
```

---

## Troubleshooting

### Error: "ARGUS_SESSION_SECRET environment variable is required in production mode"

**Cause:** You've set `ARGUS_ENVIRONMENT=production` but haven't provided a session secret.

**Solution:**

```bash
# Generate a secret
python -c 'import secrets; print(secrets.token_urlsafe(32))'

# Add to .env
echo "ARGUS_SESSION_SECRET=<generated_secret>" >> .env

# Restart Argus
```

### Error: "Config file still contains plaintext secrets"

**Cause:** Secrets weren't properly redacted in `config.yaml`.

**Solution:**

```bash
# Manually edit config.yaml
nano config.yaml

# Replace secret values with: ***REDACTED***
# Example:
#   smtp_password: ***REDACTED***

# Or re-run migration script
python migrate_secrets.py --force
```

### Error: "Permission denied reading .env"

**Cause:** `.env` file has incorrect permissions or ownership.

**Solution:**

```bash
# Fix permissions
chmod 600 .env

# Fix ownership (if running as specific user)
sudo chown argus:argus .env
```

### Secrets Not Being Loaded

**Cause:** Environment variables not accessible to Argus process.

**Debug:**

```bash
# Check if .env is in correct location
ls -la .env

# Verify environment variables are loaded
python -c "import os; print(os.environ.get('ARGUS_SESSION_SECRET', 'NOT_FOUND'))"

# Check systemd service logs
sudo journalctl -u argus -n 50

# Check Docker logs
docker-compose logs argus
```

### Migration Script Errors

**Issue:** `FileNotFoundError: config.yaml`

**Solution:**

```bash
# Run from Argus root directory
cd /path/to/argus
python migrate_secrets.py --config ./config.yaml
```

**Issue:** `yaml.YAMLError: ...`

**Solution:**

```bash
# Validate your config.yaml syntax
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Fix any YAML syntax errors
```

---

## Security Best Practices

### 1. Never Commit `.env` to Version Control

```bash
# Add to .gitignore
echo ".env" >> .gitignore
echo ".env.local" >> .gitignore
echo "*.backup.*" >> .gitignore
```

### 2. Use Strong, Unique Secrets

```bash
# Generate secure random secrets (32+ bytes)
python -c 'import secrets; print(secrets.token_urlsafe(32))'

# Or using openssl
openssl rand -base64 32
```

### 3. Rotate Secrets Regularly

```bash
# Generate new session secret
NEW_SECRET=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')

# Update .env
sed -i.bak "s/^ARGUS_SESSION_SECRET=.*/ARGUS_SESSION_SECRET=${NEW_SECRET}/" .env

# Restart Argus (invalidates all existing sessions)
sudo systemctl restart argus
```

### 4. Restrict File Permissions

```bash
# .env should only be readable by Argus user
chmod 600 .env
chown argus:argus .env

# config.yaml can be readable (no secrets)
chmod 644 config.yaml
```

### 5. Use Secrets Management Tools (Production)

For production deployments, consider:
- **HashiCorp Vault**: Centralized secrets management
- **AWS Secrets Manager**: Cloud-native secrets storage
- **Azure Key Vault**: Microsoft Azure secrets
- **Kubernetes Secrets**: Container orchestration secrets

---

## Rollback Procedure

If you need to rollback to v1.x:

### 1. Restore Backup

```bash
# Restore original config.yaml
cp config.yaml.backup.YYYYMMDD_HHMMSS config.yaml

# Or restore from specific backup
ls config.yaml.backup.*
cp config.yaml.backup.20250127_133000 config.yaml
```

### 2. Downgrade Argus

```bash
# Using git
git checkout v1.9  # Or your previous version

# Reinstall dependencies
pip install -r requirements.txt

# Restart
sudo systemctl restart argus
```

### 3. Remove v2.0 Changes (Optional)

```bash
# Remove .env if not used in v1.x
rm .env

# Clear migration artifacts
rm config.yaml.backup.*
```

---

## FAQ

### Q: Do I need to migrate if I don't have any integrations enabled?

**A:** Yes. At minimum, you must configure `ARGUS_SESSION_SECRET` for production deployments. Otherwise, session cookies will not be secure.

### Q: Can I keep using `config.yaml` for secrets?

**A:** Only in development mode (`ARGUS_ENVIRONMENT=development`). In production, this is explicitly blocked for security reasons.

### Q: What happens to existing session cookies after migration?

**A:** If you generate a new `ARGUS_SESSION_SECRET`, all existing session cookies will become invalid. Users will need to log in again.

### Q: Do API keys need to be regenerated?

**A:** No. Existing API keys continue to work. However, the authentication performance will be significantly improved (100x faster).

### Q: Is this migration reversible?

**A:** Yes, see the "Rollback Procedure" section above. However, we strongly recommend staying on v2.0 for security reasons.

### Q: How do I know if my secrets are properly loaded?

**A:** Check the Argus logs on startup. You should NOT see any warnings about "using file-based secrets" in production mode.

---

## Getting Help

If you encounter issues during migration:

1. **Check the logs**: `journalctl -u argus -n 100` or `docker-compose logs argus`
2. **Run dry-run**: `python migrate_secrets.py --dry-run`
3. **Review this guide**: Ensure all steps were followed
4. **GitHub Issues**: https://github.com/yourusername/argus/issues
5. **Security Issues**: security@argus-project.org (for sensitive security matters)

---

## Changelog Reference

See `CHANGELOG.md` for complete v2.0 release notes including:
- Command injection fixes
- API key performance optimizations
- Additional security improvements
- Other breaking changes

---

**Last Updated:** January 27, 2026  
**Applies to:** Argus v2.0.0 and later
