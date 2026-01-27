"""
Pydantic schemas for request/response validation.

This module contains all Pydantic models used for API request validation,
providing input sanitization, type checking, and security controls.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime
import html
import re
import ipaddress


# ============================================================================
# Device Schemas
# ============================================================================

class DeviceUpdate(BaseModel):
    """Schema for updating device properties"""
    label: Optional[str] = Field(None, max_length=255, min_length=1)
    notes: Optional[str] = Field(None, max_length=5000)
    is_trusted: Optional[bool] = None
    zone: Optional[str] = Field(None, max_length=100)
    
    @field_validator('label', 'notes')
    @classmethod
    def sanitize_html(cls, v):
        """Strip HTML/script tags to prevent XSS attacks"""
        if v:
            # Escape HTML entities
            sanitized = html.escape(v.strip())
            # Ensure it's not just whitespace after sanitization
            if not sanitized or sanitized.isspace():
                return None
            return sanitized
        return v
    
    @field_validator('zone')
    @classmethod
    def validate_zone(cls, v):
        """Ensure zone contains only safe characters"""
        if v:
            v = v.strip()
            # Allow alphanumeric, spaces, hyphens, underscores
            if not re.match(r'^[a-zA-Z0-9_\-\s]+$', v):
                raise ValueError(
                    "Zone must contain only letters, numbers, spaces, hyphens, and underscores"
                )
            return v
        return v


# ============================================================================
# Scan Schemas
# ============================================================================

class ScanRequest(BaseModel):
    """Schema for initiating a network scan"""
    subnet: Optional[str] = Field(None, description="Network subnet in CIDR notation", max_length=50)
    scan_profile: Optional[str] = Field("normal", pattern=r'^(quick|normal|intensive)$')
    port_range: Optional[str] = Field(None, max_length=200)
    enable_os_detection: Optional[bool] = True
    enable_service_detection: Optional[bool] = True
    detect_changes: Optional[bool] = True
    
    @field_validator('subnet')
    @classmethod
    def validate_subnet(cls, v):
        """Validate subnet is valid CIDR notation"""
        v = v.strip()
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError as e:
            raise ValueError(f"Invalid subnet format: {e}")
    
    @field_validator('port_range')
    @classmethod
    def validate_port_range(cls, v):
        """Basic validation - scanner will do detailed validation"""
        if v:
            v = v.strip()
            # Length check to prevent DoS
            if len(v) > 200:
                raise ValueError("Port range too long")
        return v


class SingleDeviceScanRequest(BaseModel):
    """Schema for scanning a single device"""
    ip_address: str = Field(..., description="Target IP address", max_length=45)
    scan_profile: Optional[str] = Field("normal", pattern=r'^(quick|normal|intensive)$')
    port_range: Optional[str] = Field("1-1000", max_length=200)
    enable_os_detection: Optional[bool] = True
    enable_service_detection: Optional[bool] = True
    
    @field_validator('ip_address')
    @classmethod
    def validate_ip(cls, v):
        """Validate IP address format (IPv4 or IPv6)"""
        v = v.strip()
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError("Invalid IP address format")


# ============================================================================
# Configuration Schemas
# ============================================================================

class NetworkConfigUpdate(BaseModel):
    """Schema for network configuration updates"""
    subnet: str = Field(..., max_length=50)
    scan_profile: str = Field(..., pattern=r'^(quick|normal|intensive)$')
    
    @field_validator('subnet')
    @classmethod
    def validate_subnet(cls, v):
        """Validate subnet format"""
        v = v.strip()
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError:
            raise ValueError("Invalid subnet format")


class ScanningConfigUpdate(BaseModel):
    """Schema for scanning configuration updates"""
    port_range: str = Field(..., max_length=200)
    enable_os_detection: bool


class ConfigUpdate(BaseModel):
    """Schema for general configuration updates"""
    network: NetworkConfigUpdate
    scanning: ScanningConfigUpdate


# ============================================================================
# Integration Schemas
# ============================================================================

class CVEIntegrationUpdate(BaseModel):
    """Schema for CVE integration configuration"""
    enabled: bool
    api_key: Optional[str] = Field(None, min_length=1, max_length=500)
    cache_hours: int = Field(24, ge=1, le=168)  # 1 hour to 1 week
    
    @field_validator('api_key')
    @classmethod
    def validate_api_key(cls, v):
        """Validate API key format"""
        if v:
            v = v.strip()
            # Ensure it's not empty after stripping
            if not v:
                return None
            return v
        return v


class UniFiIntegrationUpdate(BaseModel):
    """Schema for UniFi integration configuration"""
    enabled: bool
    controller_url: str = Field("", max_length=500)
    controller_type: str = Field("udm", pattern=r'^(udm|cloudkey|standalone)$')
    username: Optional[str] = Field(None, max_length=255)
    password: Optional[str] = Field(None, max_length=255)
    api_key: Optional[str] = Field(None, max_length=500)
    site_id: str = Field("default", max_length=100)
    verify_ssl: bool = False
    cache_seconds: int = Field(60, ge=0, le=3600)
    sync_on_scan: bool = True
    include_offline_clients: bool = False
    
    @field_validator('controller_url')
    @classmethod
    def validate_url(cls, v):
        """Validate URL format"""
        if v and v.strip():
            v = v.strip()
            # Basic URL validation - must start with http:// or https://
            if not re.match(r'^https?://', v):
                raise ValueError("Controller URL must start with http:// or https://")
            return v
        return v


class PiHoleIntegrationUpdate(BaseModel):
    """Schema for Pi-hole integration configuration"""
    enabled: bool
    pihole_url: str = Field("", max_length=500)
    api_token: Optional[str] = Field(None, max_length=500)
    verify_ssl: bool = False
    cache_seconds: int = Field(60, ge=0, le=3600)
    sync_on_scan: bool = True
    
    @field_validator('pihole_url')
    @classmethod
    def validate_url(cls, v):
        """Validate URL format"""
        if v and v.strip():
            v = v.strip()
            # Basic URL validation - must start with http:// or https://
            if not re.match(r'^https?://', v):
                raise ValueError("Pi-hole URL must start with http:// or https://")
            return v
        return v


class AdGuardIntegrationUpdate(BaseModel):
    """Schema for AdGuard integration configuration"""
    enabled: bool
    adguard_url: str = Field("", max_length=500)
    username: Optional[str] = Field(None, max_length=255)
    password: Optional[str] = Field(None, max_length=255)
    verify_ssl: bool = False
    cache_seconds: int = Field(60, ge=0, le=3600)
    sync_on_scan: bool = True
    
    @field_validator('adguard_url')
    @classmethod
    def validate_url(cls, v):
        """Validate URL format"""
        if v and v.strip():
            v = v.strip()
            # Basic URL validation - must start with http:// or https://
            if not re.match(r'^https?://', v):
                raise ValueError("AdGuard URL must start with http:// or https://")
            return v
        return v


# ============================================================================
# API Key Schemas
# ============================================================================

class APIKeyCreateRequest(BaseModel):
    """Schema for creating a new API key"""
    name: str = Field(..., min_length=1, max_length=100)
    expires_in_days: Optional[int] = Field(None, ge=1, le=3650, description="Days until expiration (1-3650)")
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        """Validate API key name"""
        v = v.strip()
        # Allow alphanumeric, spaces, hyphens, underscores
        if not re.match(r'^[a-zA-Z0-9_\-\s]+$', v):
            raise ValueError(
                "Name must contain only letters, numbers, spaces, hyphens, and underscores"
            )
        return v


# ============================================================================
# Schedule Schemas
# ============================================================================

class ScheduleJobCreate(BaseModel):
    """Schema for creating a scheduled scan job"""
    name: str = Field(..., min_length=1, max_length=100)
    cron: str = Field(..., max_length=100)
    profile: str = Field("normal", pattern=r'^(quick|normal|intensive)$')
    enabled: Optional[bool] = True
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        """Validate job name"""
        v = v.strip()
        if not re.match(r'^[a-zA-Z0-9_\-\s]+$', v):
            raise ValueError(
                "Name must contain only letters, numbers, spaces, hyphens, and underscores"
            )
        return v
    
    @field_validator('cron')
    @classmethod
    def validate_cron(cls, v):
        """Basic cron expression validation"""
        v = v.strip()
        # Basic validation: should have 5 parts (minute hour day month weekday)
        parts = v.split()
        if len(parts) != 5:
            raise ValueError("Cron expression must have 5 fields (minute hour day month weekday)")
        return v


class ScheduleJobUpdate(BaseModel):
    """Schema for updating a scheduled scan job"""
    name: str = Field(..., min_length=1, max_length=100)
    cron: str = Field(..., max_length=100)
    profile: str = Field("normal", pattern=r'^(quick|normal|intensive)$')
    enabled: Optional[bool] = True
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        """Validate job name"""
        v = v.strip()
        if not re.match(r'^[a-zA-Z0-9_\-\s]+$', v):
            raise ValueError(
                "Name must contain only letters, numbers, spaces, hyphens, and underscores"
            )
        return v
    
    @field_validator('cron')
    @classmethod
    def validate_cron(cls, v):
        """Basic cron expression validation"""
        v = v.strip()
        parts = v.split()
        if len(parts) != 5:
            raise ValueError("Cron expression must have 5 fields")
        return v


# ============================================================================
# Response Schemas (existing ones from main.py)
# ============================================================================

class ScanResponse(BaseModel):
    """Response schema for scan operations"""
    id: int
    started_at: datetime
    completed_at: Optional[datetime]
    status: str
    subnet: str
    devices_found: int
    scan_profile: str

    class Config:
        from_attributes = True


class PortResponse(BaseModel):
    """Response schema for port information"""
    port_number: int
    protocol: str
    state: str
    service_name: Optional[str]
    service_version: Optional[str]

    class Config:
        from_attributes = True


class APIKeyCreatedResponse(BaseModel):
    """Response schema for created API key (includes plaintext key once)"""
    id: int
    name: str
    key: str  # Only returned on creation
    key_prefix: str
    created_at: datetime
    expires_at: Optional[datetime]

    class Config:
        from_attributes = True
