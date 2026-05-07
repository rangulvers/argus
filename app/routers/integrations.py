"""Integration management routes (CVE, UniFi, Pi-hole, AdGuard)."""
import logging
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import get_config, save_config, reload_config
from app.audit import log_from_request, AuditAction, ResourceType
from app.schemas import (
    CVEIntegrationUpdate,
    UniFiIntegrationUpdate,
    PiHoleIntegrationUpdate,
    AdGuardIntegrationUpdate,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ==================== CVE Integration ====================

@router.get("/api/integrations/cve")
async def get_cve_integration():
    """Get CVE integration settings"""
    config = get_config()
    return {
        "enabled": config.integrations.cve.enabled,
        "api_key": config.integrations.cve.api_key,
        "api_url": config.integrations.cve.api_url,
        "cache_hours": config.integrations.cve.cache_hours
    }


@router.put("/api/integrations/cve")
async def update_cve_integration(
    cve_update: CVEIntegrationUpdate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Update CVE integration settings"""
    try:
        config = get_config()

        # Track changes for audit
        old_settings = {
            "enabled": config.integrations.cve.enabled,
            "cache_hours": config.integrations.cve.cache_hours,
            "has_api_key": bool(config.integrations.cve.api_key)
        }

        # Update settings
        config.integrations.cve.enabled = cve_update.enabled
        config.integrations.cve.api_key = cve_update.api_key
        config.integrations.cve.cache_hours = cve_update.cache_hours

        # Save to YAML file
        save_config(config)

        # Reload config to ensure consistency
        reload_config()

        # Log config update
        log_from_request(
            db=db,
            request=request,
            action=AuditAction.CONFIG_UPDATED,
            resource_type=ResourceType.CONFIG,
            details={
                "integration": "cve",
                "old": old_settings,
                "new": {
                    "enabled": cve_update.enabled,
                    "cache_hours": cve_update.cache_hours,
                    "has_api_key": bool(cve_update.api_key)
                }
            }
        )

        return {
            "status": "success",
            "message": "CVE integration settings updated",
            "enabled": cve_update.enabled,
            "cache_hours": cve_update.cache_hours
        }
    except Exception as e:
        logger.error(f"Failed to update CVE integration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update settings: {str(e)}")


@router.post("/api/integrations/cve/test")
async def test_cve_connection():
    """Test connection to NVD API"""
    import aiohttp

    config = get_config()

    try:
        # Test the NVD API with a simple request
        headers = {}
        if config.integrations.cve.api_key:
            headers["apiKey"] = config.integrations.cve.api_key

        async with aiohttp.ClientSession() as session:
            # Test with a simple CVE lookup
            async with session.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    return {
                        "status": "connected",
                        "details": {
                            "has_api_key": bool(config.integrations.cve.api_key)
                        }
                    }
                else:
                    return {
                        "status": "error",
                        "error_message": f"API returned status {response.status}"
                    }
    except Exception as e:
        logger.error(f"CVE API test failed: {e}")
        return {
            "status": "error",
            "error_message": f"Connection failed: {str(e)}"
        }


# ==================== UniFi Integration ====================

@router.get("/api/integrations/unifi")
async def get_unifi_integration():
    """Get UniFi integration settings"""
    config = get_config()
    return {
        "enabled": config.integrations.unifi.enabled,
        "controller_url": config.integrations.unifi.controller_url,
        "controller_type": config.integrations.unifi.controller_type,
        "username": config.integrations.unifi.username,
        "has_password": bool(config.integrations.unifi.password),
        "has_api_key": bool(config.integrations.unifi.api_key),
        "site_id": config.integrations.unifi.site_id,
        "verify_ssl": config.integrations.unifi.verify_ssl,
        "cache_seconds": config.integrations.unifi.cache_seconds,
        "sync_on_scan": config.integrations.unifi.sync_on_scan,
        "include_offline_clients": config.integrations.unifi.include_offline_clients,
    }


@router.put("/api/integrations/unifi")
async def update_unifi_integration(
    unifi_update: UniFiIntegrationUpdate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Update UniFi integration settings"""
    try:
        config = get_config()

        # Track changes for audit
        old_enabled = config.integrations.unifi.enabled

        # Update settings
        config.integrations.unifi.enabled = unifi_update.enabled
        config.integrations.unifi.controller_url = unifi_update.controller_url
        config.integrations.unifi.controller_type = unifi_update.controller_type
        config.integrations.unifi.site_id = unifi_update.site_id
        config.integrations.unifi.verify_ssl = unifi_update.verify_ssl
        config.integrations.unifi.cache_seconds = unifi_update.cache_seconds
        config.integrations.unifi.sync_on_scan = unifi_update.sync_on_scan
        config.integrations.unifi.include_offline_clients = unifi_update.include_offline_clients

        # Only update credentials if provided (not None)
        if unifi_update.username is not None:
            config.integrations.unifi.username = unifi_update.username
        if unifi_update.password is not None:
            config.integrations.unifi.password = unifi_update.password
        if unifi_update.api_key is not None:
            config.integrations.unifi.api_key = unifi_update.api_key

        # Save to YAML
        save_config(config)
        reload_config()

        # Log config update
        log_from_request(
            db=db,
            request=request,
            action=AuditAction.CONFIG_UPDATED,
            resource_type=ResourceType.CONFIG,
            details={
                "integration": "unifi",
                "enabled_changed": old_enabled != unifi_update.enabled,
                "new_enabled": unifi_update.enabled,
            }
        )

        return {
            "status": "success",
            "message": "UniFi integration settings updated",
            "enabled": unifi_update.enabled
        }
    except Exception as e:
        logger.error(f"Failed to update UniFi integration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update settings: {str(e)}")


@router.post("/api/integrations/unifi/test")
async def test_unifi_connection():
    """Test connection to UniFi controller"""
    from app.integrations.unifi.enricher import UniFiEnricher
    import logging

    logger = logging.getLogger(__name__)
    config = get_config()

    if not config.integrations.unifi.controller_url:
        return {
            "status": "error",
            "error_message": "No controller URL configured"
        }

    # Check authentication is configured
    has_credentials = config.integrations.unifi.username and config.integrations.unifi.password
    has_api_key = config.integrations.unifi.api_key
    if not has_credentials and not has_api_key:
        return {
            "status": "error",
            "error_message": "No authentication configured. Please set username/password or API key."
        }

    try:
        logger.info(f"Testing UniFi connection to {config.integrations.unifi.controller_url}")

        # Create enricher with current config
        enricher = UniFiEnricher(
            enabled=True,  # Force enabled for test
            controller_url=config.integrations.unifi.controller_url,
            controller_type=config.integrations.unifi.controller_type,
            username=config.integrations.unifi.username,
            password=config.integrations.unifi.password,
            api_key=config.integrations.unifi.api_key,
            site_id=config.integrations.unifi.site_id,
            verify_ssl=config.integrations.unifi.verify_ssl,
        )

        health = await enricher.test_connection()

        return {
            "status": health.status.value,
            "last_check": health.last_check.isoformat() if health.last_check else None,
            "error_message": health.error_message,
            "details": health.details
        }
    except Exception as e:
        logger.error(f"UniFi test connection failed: {e}")
        return {
            "status": "error",
            "error_message": f"Connection test failed: {str(e)}"
        }


@router.get("/api/integrations/unifi/clients")
async def get_unifi_clients():
    """Get all clients from UniFi controller"""
    from app.integrations.unifi.enricher import UniFiEnricher

    config = get_config()

    if not config.integrations.unifi.enabled:
        raise HTTPException(status_code=400, detail="UniFi integration is not enabled")

    enricher = UniFiEnricher(
        enabled=config.integrations.unifi.enabled,
        controller_url=config.integrations.unifi.controller_url,
        controller_type=config.integrations.unifi.controller_type,
        username=config.integrations.unifi.username,
        password=config.integrations.unifi.password,
        api_key=config.integrations.unifi.api_key,
        site_id=config.integrations.unifi.site_id,
        verify_ssl=config.integrations.unifi.verify_ssl,
        cache_seconds=config.integrations.unifi.cache_seconds,
        include_offline_clients=config.integrations.unifi.include_offline_clients,
    )

    try:
        data = await enricher.get_data()
        return data
    except Exception as e:
        logger.error(f"Failed to get UniFi clients: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Pi-hole Integration ====================

@router.get("/api/integrations/pihole")
async def get_pihole_integration():
    """Get Pi-hole integration settings"""
    config = get_config()
    return {
        "enabled": config.integrations.pihole.enabled,
        "pihole_url": config.integrations.pihole.pihole_url,
        "has_api_token": bool(config.integrations.pihole.api_token),
        "verify_ssl": config.integrations.pihole.verify_ssl,
        "cache_seconds": config.integrations.pihole.cache_seconds,
        "sync_on_scan": config.integrations.pihole.sync_on_scan,
    }


@router.put("/api/integrations/pihole")
async def update_pihole_integration(
    pihole_update: PiHoleIntegrationUpdate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Update Pi-hole integration settings"""
    try:
        config = get_config()

        # Track changes for audit
        old_enabled = config.integrations.pihole.enabled

        # Update settings
        config.integrations.pihole.enabled = pihole_update.enabled
        config.integrations.pihole.pihole_url = pihole_update.pihole_url
        config.integrations.pihole.verify_ssl = pihole_update.verify_ssl
        config.integrations.pihole.cache_seconds = pihole_update.cache_seconds
        config.integrations.pihole.sync_on_scan = pihole_update.sync_on_scan

        # Only update API token if provided (not None)
        if pihole_update.api_token is not None:
            config.integrations.pihole.api_token = pihole_update.api_token

        # Save to YAML
        save_config(config)
        reload_config()

        # Log config update
        log_from_request(
            db=db,
            request=request,
            action=AuditAction.CONFIG_UPDATED,
            resource_type=ResourceType.CONFIG,
            details={
                "integration": "pihole",
                "enabled_changed": old_enabled != pihole_update.enabled,
                "new_enabled": pihole_update.enabled,
            }
        )

        return {
            "status": "success",
            "message": "Pi-hole integration settings updated",
            "enabled": pihole_update.enabled
        }
    except Exception as e:
        logger.error(f"Failed to update Pi-hole integration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update settings: {str(e)}")


@router.post("/api/integrations/pihole/test")
async def test_pihole_connection():
    """Test connection to Pi-hole"""
    from app.integrations.pihole.enricher import PiHoleEnricher
    import logging

    logger = logging.getLogger(__name__)
    config = get_config()

    if not config.integrations.pihole.pihole_url:
        return {
            "status": "error",
            "error_message": "No Pi-hole URL configured"
        }

    try:
        logger.info(f"Testing Pi-hole connection to {config.integrations.pihole.pihole_url}")

        # Create enricher with current config
        enricher = PiHoleEnricher(
            enabled=True,  # Force enabled for test
            pihole_url=config.integrations.pihole.pihole_url,
            api_token=config.integrations.pihole.api_token,
            verify_ssl=config.integrations.pihole.verify_ssl,
        )

        health = await enricher.test_connection()

        return {
            "status": health.status.value,
            "last_check": health.last_check.isoformat() if health.last_check else None,
            "error_message": health.error_message,
            "details": health.details
        }
    except Exception as e:
        logger.error(f"Pi-hole test connection failed: {e}")
        return {
            "status": "error",
            "error_message": f"Connection test failed: {str(e)}"
        }


@router.get("/api/integrations/pihole/stats")
async def get_pihole_stats():
    """Get Pi-hole statistics"""
    from app.integrations.pihole.enricher import PiHoleEnricher

    config = get_config()

    if not config.integrations.pihole.enabled:
        raise HTTPException(status_code=400, detail="Pi-hole integration is not enabled")

    enricher = PiHoleEnricher(
        enabled=config.integrations.pihole.enabled,
        pihole_url=config.integrations.pihole.pihole_url,
        api_token=config.integrations.pihole.api_token,
        verify_ssl=config.integrations.pihole.verify_ssl,
        cache_seconds=config.integrations.pihole.cache_seconds,
    )

    try:
        data = await enricher.get_data()
        return data
    except Exception as e:
        logger.error(f"Failed to get Pi-hole stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== AdGuard Home Integration ====================

@router.get("/api/integrations/adguard")
async def get_adguard_integration():
    """Get AdGuard Home integration settings"""
    config = get_config()
    return {
        "enabled": config.integrations.adguard.enabled,
        "adguard_url": config.integrations.adguard.adguard_url,
        "username": config.integrations.adguard.username,
        "has_password": bool(config.integrations.adguard.password),
        "verify_ssl": config.integrations.adguard.verify_ssl,
        "cache_seconds": config.integrations.adguard.cache_seconds,
        "sync_on_scan": config.integrations.adguard.sync_on_scan,
    }


@router.put("/api/integrations/adguard")
async def update_adguard_integration(
    adguard_update: AdGuardIntegrationUpdate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Update AdGuard Home integration settings"""
    try:
        config = get_config()

        # Track changes for audit
        old_enabled = config.integrations.adguard.enabled

        # Update settings
        config.integrations.adguard.enabled = adguard_update.enabled
        config.integrations.adguard.adguard_url = adguard_update.adguard_url
        config.integrations.adguard.verify_ssl = adguard_update.verify_ssl
        config.integrations.adguard.cache_seconds = adguard_update.cache_seconds
        config.integrations.adguard.sync_on_scan = adguard_update.sync_on_scan

        # Only update credentials if provided (not None)
        if adguard_update.username is not None:
            config.integrations.adguard.username = adguard_update.username
        if adguard_update.password is not None:
            config.integrations.adguard.password = adguard_update.password

        # Save to YAML
        save_config(config)
        reload_config()

        # Log config update
        log_from_request(
            db=db,
            request=request,
            action=AuditAction.CONFIG_UPDATED,
            resource_type=ResourceType.CONFIG,
            details={
                "integration": "adguard",
                "enabled_changed": old_enabled != adguard_update.enabled,
                "new_enabled": adguard_update.enabled,
            }
        )

        return {
            "status": "success",
            "message": "AdGuard Home integration settings updated",
            "enabled": adguard_update.enabled
        }
    except Exception as e:
        logger.error(f"Failed to update AdGuard Home integration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update settings: {str(e)}")


@router.post("/api/integrations/adguard/test")
async def test_adguard_connection():
    """Test connection to AdGuard Home"""
    from app.integrations.adguard.enricher import AdGuardEnricher
    import logging

    logger = logging.getLogger(__name__)
    config = get_config()

    if not config.integrations.adguard.adguard_url:
        return {
            "status": "error",
            "error_message": "No AdGuard Home URL configured"
        }

    try:
        logger.info(f"Testing AdGuard Home connection to {config.integrations.adguard.adguard_url}")

        # Create enricher with current config
        enricher = AdGuardEnricher(
            enabled=True,  # Force enabled for test
            adguard_url=config.integrations.adguard.adguard_url,
            username=config.integrations.adguard.username,
            password=config.integrations.adguard.password,
            verify_ssl=config.integrations.adguard.verify_ssl,
        )

        health = await enricher.test_connection()

        return {
            "status": health.status.value,
            "last_check": health.last_check.isoformat() if health.last_check else None,
            "error_message": health.error_message,
            "details": health.details
        }
    except Exception as e:
        logger.error(f"AdGuard Home test connection failed: {e}")
        return {
            "status": "error",
            "error_message": f"Connection test failed: {str(e)}"
        }


@router.get("/api/integrations/adguard/stats")
async def get_adguard_stats():
    """Get AdGuard Home statistics"""
    from app.integrations.adguard.enricher import AdGuardEnricher

    config = get_config()

    if not config.integrations.adguard.enabled:
        raise HTTPException(status_code=400, detail="AdGuard Home integration is not enabled")

    enricher = AdGuardEnricher(
        enabled=config.integrations.adguard.enabled,
        adguard_url=config.integrations.adguard.adguard_url,
        username=config.integrations.adguard.username,
        password=config.integrations.adguard.password,
        verify_ssl=config.integrations.adguard.verify_ssl,
        cache_seconds=config.integrations.adguard.cache_seconds,
    )

    try:
        data = await enricher.get_data()
        return data
    except Exception as e:
        logger.error(f"Failed to get AdGuard Home stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/network/detect")
async def detect_network():
    """Detect local network configuration.

    Returns the host's IP address and suggested subnet for scanning.
    Useful for initial setup to auto-populate the scan range.
    """
    from app.utils.network_utils import get_network_info
    return get_network_info()
