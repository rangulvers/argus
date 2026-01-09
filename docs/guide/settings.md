# Settings

The Settings page allows you to configure Argus and manage security features.

## Network Configuration

### Subnet

The network range to scan in CIDR notation.

```
192.168.1.0/24    # Standard home network
10.0.0.0/24       # Alternative range
172.16.0.0/16     # Larger network
```

### Scan Profile

Default scan intensity for scheduled and quick-triggered scans:

- **Quick** - Device discovery only
- **Normal** - Port scan + service detection
- **Intensive** - Full analysis

## Scanning Options

### Port Range

Which ports to scan:

| Option | Description |
|--------|-------------|
| `1-1000` | First 1000 ports (default) |
| `1-65535` | All ports |
| `common` | Nmap's common ports |
| `22,80,443` | Specific ports |

### OS Detection

Enable/disable operating system fingerprinting.

!!! note
    OS detection requires elevated privileges and may slow scans.

## Scheduled Scans

Create automatic scan schedules:

### Adding a Schedule

1. Click **"Add Schedule"**
2. Enter a name (e.g., "Nightly Security Scan")
3. Set the cron expression
4. Choose scan profile
5. Click **"Create"**

### Cron Expression Examples

| Expression | Schedule |
|------------|----------|
| `0 2 * * *` | Daily at 2 AM |
| `0 */6 * * *` | Every 6 hours |
| `0 2 * * 0` | Sunday at 2 AM |
| `0 2 1 * *` | First of month at 2 AM |
| `*/30 * * * *` | Every 30 minutes |

### Managing Schedules

- **Enable/Disable** - Toggle the switch
- **Edit** - Click the pencil icon
- **Delete** - Click the trash icon

## API Keys

API keys allow programmatic access to Argus without session cookies.

### Creating an API Key

1. Scroll to **API Keys** section
2. Click **"Create API Key"**
3. Enter a descriptive name
4. Copy the generated key immediately

!!! warning "Security"
    The full API key is only shown once. Store it securely - it cannot be retrieved later.

### Using API Keys

Include the key in your requests:

=== "X-API-Key Header"

    ```bash
    curl -H "X-API-Key: argus_xxxxx" http://localhost:8080/api/devices
    ```

=== "Bearer Token"

    ```bash
    curl -H "Authorization: Bearer argus_xxxxx" http://localhost:8080/api/devices
    ```

### Revoking Keys

Click **"Revoke"** next to any key to immediately invalidate it.

### Key Information

- **Name** - Your description
- **Prefix** - First 8 characters for identification
- **Created** - When the key was created
- **Last Used** - Most recent API call

## Audit Log

View a history of security-relevant actions:

### Logged Actions

| Action | Description |
|--------|-------------|
| `login_success` | Successful login |
| `login_failed` | Failed login attempt |
| `logout` | User logged out |
| `scan_started` | Scan initiated |
| `scan_completed` | Scan finished |
| `device_updated` | Device settings changed |
| `api_key_created` | New API key generated |
| `api_key_revoked` | API key revoked |
| `config_updated` | Settings changed |

### Log Details

Each entry shows:

- **Timestamp** - When it occurred
- **User** - Who performed the action
- **Action** - What was done
- **Resource** - What was affected
- **IP Address** - Client IP
- **Status** - Success or failure

### Filtering

Use the action dropdown to filter by event type.

### Loading More

Click **"Load More"** to see older entries.

## Configuration File

Settings are persisted to `config.yaml`. The file is automatically updated when you save changes in the UI.

### Manual Editing

You can also edit `config.yaml` directly:

```yaml
network:
  subnet: "192.168.1.0/24"
  scan_profile: "normal"

scanning:
  port_range: "1-1000"
  enable_os_detection: true
  enable_service_detection: true
```

After editing, restart Argus or click **"Reload Config"** in settings.

## Security Best Practices

!!! tip "API Keys"
    - Create separate keys for different integrations
    - Use descriptive names
    - Revoke unused keys
    - Rotate keys periodically

!!! tip "Audit Log"
    - Review failed login attempts
    - Monitor for unexpected config changes
    - Check for unusual scan patterns

!!! warning "Authentication"
    - Use a strong admin password
    - Don't share credentials
    - Log out when not in use
