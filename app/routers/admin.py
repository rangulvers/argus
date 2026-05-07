"""Admin and audit log routes."""
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models import AuditLog
from app.audit import AuditAction
from pydantic import BaseModel
from datetime import datetime

logger = logging.getLogger(__name__)
router = APIRouter()


class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    username: Optional[str]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    details: Optional[dict]
    ip_address: Optional[str]
    success: bool

    class Config:
        from_attributes = True


@router.get("/api/audit-logs", response_model=List[AuditLogResponse])
async def list_audit_logs(
    limit: int = 50,
    offset: int = 0,
    action: Optional[str] = None,
    username: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List audit logs with optional filtering"""
    query = db.query(AuditLog)

    # Apply filters
    if action:
        query = query.filter(AuditLog.action == action)
    if username:
        query = query.filter(AuditLog.username == username)

    # Order by most recent first
    logs = query.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit).all()

    return logs


@router.get("/api/audit-logs/actions")
async def list_audit_actions():
    """List all available audit action types"""
    return {
        "actions": [
            {"value": AuditAction.LOGIN_SUCCESS, "label": "Login Success"},
            {"value": AuditAction.LOGIN_FAILED, "label": "Login Failed"},
            {"value": AuditAction.LOGOUT, "label": "Logout"},
            {"value": AuditAction.SETUP_COMPLETE, "label": "Setup Complete"},
            {"value": AuditAction.API_KEY_CREATED, "label": "API Key Created"},
            {"value": AuditAction.API_KEY_REVOKED, "label": "API Key Revoked"},
            {"value": AuditAction.SCAN_STARTED, "label": "Scan Started"},
            {"value": AuditAction.SCAN_COMPLETED, "label": "Scan Completed"},
            {"value": AuditAction.DEVICE_UPDATED, "label": "Device Updated"},
            {"value": AuditAction.CONFIG_UPDATED, "label": "Config Updated"},
        ]
    }
