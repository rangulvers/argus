#!/usr/bin/env python3
"""
Argus Secrets Migration Script (v1.x to v2.0)

This script migrates secrets from config.yaml to environment variables (.env file)
as part of the v2.0 security improvements.

Usage:
    python migrate_secrets.py [--dry-run] [--force]

Options:
    --dry-run    Show what would be migrated without making changes
    --force      Overwrite existing .env file if it exists
"""

import argparse
import os
import sys
import yaml
import shutil
from datetime import datetime
from pathlib import Path


# Define secret field mappings: (config_path, env_var_name)
SECRET_MAPPINGS = [
    # Email configuration
    ("email.smtp_password", "ARGUS_EMAIL_SMTP_PASSWORD"),
    
    # Webhook configuration
    ("webhook.secret", "ARGUS_WEBHOOK_SECRET"),
    
    # CVE integration
    ("cve_integration.api_key", "ARGUS_CVE_API_KEY"),
    
    # UniFi integration
    ("unifi_integration.password", "ARGUS_UNIFI_PASSWORD"),
    ("unifi_integration.api_key", "ARGUS_UNIFI_API_KEY"),
    
    # Pi-hole integration
    ("pihole_integration.api_token", "ARGUS_PIHOLE_API_TOKEN"),
    
    # AdGuard integration
    ("adguard_integration.password", "ARGUS_ADGUARD_PASSWORD"),
]


def get_nested_value(config, path):
    """Get a nested value from config using dot notation path"""
    keys = path.split(".")
    value = config
    
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    
    return value


def set_nested_value(config, path, value):
    """Set a nested value in config using dot notation path"""
    keys = path.split(".")
    current = config
    
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]
    
    current[keys[-1]] = value


def extract_secrets(config_path):
    """Extract secrets from config.yaml file"""
    if not os.path.exists(config_path):
        print(f"❌ Error: Config file not found: {config_path}")
        sys.exit(1)
    
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"❌ Error reading config file: {e}")
        sys.exit(1)
    
    # Extract secrets
    secrets = {}
    for config_path_str, env_var in SECRET_MAPPINGS:
        value = get_nested_value(config, config_path_str)
        if value and value not in ["", "***REDACTED***"]:
            secrets[env_var] = value
    
    return config, secrets


def generate_env_content(secrets):
    """Generate .env file content from secrets"""
    lines = [
        "# Argus Secrets - Migrated from config.yaml",
        f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "#",
        "# IMPORTANT: Keep this file secure and never commit it to version control",
        "",
    ]
    
    if not secrets:
        lines.append("# No secrets found to migrate")
        return "\n".join(lines)
    
    # Group secrets by category
    categories = {
        "Session Secret": [],
        "Email Notifications": [],
        "Webhook Notifications": [],
        "CVE Integration": [],
        "UniFi Integration": [],
        "Pi-hole Integration": [],
        "AdGuard Integration": [],
    }
    
    for env_var, value in secrets.items():
        if "EMAIL" in env_var:
            categories["Email Notifications"].append((env_var, value))
        elif "WEBHOOK" in env_var:
            categories["Webhook Notifications"].append((env_var, value))
        elif "CVE" in env_var:
            categories["CVE Integration"].append((env_var, value))
        elif "UNIFI" in env_var:
            categories["UniFi Integration"].append((env_var, value))
        elif "PIHOLE" in env_var:
            categories["Pi-hole Integration"].append((env_var, value))
        elif "ADGUARD" in env_var:
            categories["AdGuard Integration"].append((env_var, value))
    
    # Add session secret recommendation
    lines.extend([
        "# Session Secret (REQUIRED in production)",
        "# Generate with: python -c 'import secrets; print(secrets.token_urlsafe(32))'",
        "ARGUS_SESSION_SECRET=your_secure_session_secret_here",
        "",
    ])
    
    # Add secrets by category
    for category, items in categories.items():
        if items:
            lines.append(f"# {category}")
            for env_var, value in items:
                lines.append(f"{env_var}={value}")
            lines.append("")
    
    return "\n".join(lines)


def redact_secrets_in_config(config):
    """Replace secrets in config dict with ***REDACTED***"""
    for config_path_str, _ in SECRET_MAPPINGS:
        value = get_nested_value(config, config_path_str)
        if value and value not in ["", "***REDACTED***"]:
            set_nested_value(config, config_path_str, "***REDACTED***")
    
    return config


def backup_file(file_path):
    """Create a timestamped backup of a file"""
    if not os.path.exists(file_path):
        return None
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{file_path}.backup.{timestamp}"
    shutil.copy2(file_path, backup_path)
    return backup_path


def set_file_permissions(file_path):
    """Set restrictive permissions on file (600 - owner read/write only)"""
    try:
        os.chmod(file_path, 0o600)
        return True
    except Exception as e:
        print(f"⚠️  Warning: Could not set restrictive permissions on {file_path}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Migrate Argus secrets from config.yaml to .env file"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be migrated without making changes"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing .env file if it exists"
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config.yaml file (default: config.yaml)"
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("Argus Secrets Migration Script (v1.x → v2.0)")
    print("=" * 70)
    print()
    
    # Check for existing .env file
    env_file = ".env"
    if os.path.exists(env_file) and not args.force and not args.dry_run:
        print(f"❌ Error: {env_file} already exists")
        print(f"   Use --force to overwrite or --dry-run to preview")
        sys.exit(1)
    
    # Extract secrets from config.yaml
    print(f"📖 Reading config file: {args.config}")
    config, secrets = extract_secrets(args.config)
    
    if not secrets:
        print()
        print("ℹ️  No secrets found in config.yaml to migrate")
        print("   Either secrets are already redacted or config.yaml doesn't contain any")
        return
    
    print(f"✅ Found {len(secrets)} secret(s) to migrate:")
    print()
    
    for env_var, value in secrets.items():
        # Show first 4 and last 4 characters only
        if len(value) > 8:
            masked_value = f"{value[:4]}...{value[-4:]}"
        else:
            masked_value = "***"
        print(f"   • {env_var}: {masked_value}")
    
    print()
    
    if args.dry_run:
        print("🔍 DRY RUN MODE - No changes will be made")
        print()
        print("Would create/update .env file with:")
        print("-" * 70)
        print(generate_env_content(secrets))
        print("-" * 70)
        print()
        print("Would update config.yaml with redacted secrets")
        return
    
    # Backup config.yaml
    print("💾 Creating backup of config.yaml...")
    backup_path = backup_file(args.config)
    if backup_path:
        print(f"✅ Backup created: {backup_path}")
    
    # Create/update .env file
    print(f"📝 Writing secrets to {env_file}...")
    env_content = generate_env_content(secrets)
    
    try:
        with open(env_file, "w") as f:
            f.write(env_content)
        print(f"✅ {env_file} created successfully")
        
        # Set restrictive permissions
        if set_file_permissions(env_file):
            print(f"✅ Set restrictive permissions (600) on {env_file}")
    except Exception as e:
        print(f"❌ Error writing {env_file}: {e}")
        sys.exit(1)
    
    # Update config.yaml with redacted secrets
    print(f"🔒 Redacting secrets in {args.config}...")
    redacted_config = redact_secrets_in_config(config)
    
    try:
        with open(args.config, "w") as f:
            yaml.dump(redacted_config, f, default_flow_style=False, sort_keys=False)
        print(f"✅ {args.config} updated with redacted secrets")
    except Exception as e:
        print(f"❌ Error updating {args.config}: {e}")
        print(f"   You can restore from backup: {backup_path}")
        sys.exit(1)
    
    # Summary
    print()
    print("=" * 70)
    print("✅ Migration completed successfully!")
    print("=" * 70)
    print()
    print("Next steps:")
    print("  1. Review the .env file and ensure all secrets are correct")
    print("  2. Generate a secure session secret:")
    print("     python -c 'import secrets; print(secrets.token_urlsafe(32))'")
    print("  3. Add ARGUS_SESSION_SECRET=<generated_secret> to .env")
    print("  4. Set ARGUS_ENVIRONMENT=production in .env (optional)")
    print("  5. Restart Argus to use the new configuration")
    print("  6. NEVER commit .env to version control!")
    print()
    print(f"📋 Backup of original config: {backup_path}")
    print()


if __name__ == "__main__":
    main()
