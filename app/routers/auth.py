"""Authentication and API key management routes."""
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Request, Form, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, APIKey, Scan, Device
from app.auth import (
    hash_password, verify_password, set_session_cookie,
    clear_session_cookie, get_current_user,
    generate_api_key, hash_api_key, get_api_key_prefix
)
from app.config import get_config, save_config
from app.scanner import NetworkScanner
from app.utils.change_detector import ChangeDetector
from app.templates_config import templates
from app.audit import log_action, log_from_request, AuditAction, ResourceType
from app.schemas import APIKeyCreateRequest, APIKeyCreatedResponse

logger = logging.getLogger(__name__)
router = APIRouter()


class APIKeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    created_at: datetime
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    is_revoked: bool

    class Config:
        from_attributes = True


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, db: Session = Depends(get_db)):
    """Login page"""
    # If no users exist, redirect to setup
    user_count = db.query(User).count()
    if user_count == 0:
        return RedirectResponse(url="/setup", status_code=302)

    # If already logged in, redirect to dashboard
    current_user = get_current_user(request)
    if current_user:
        return RedirectResponse(url="/", status_code=302)

    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": None,
        "username": None
    })


from slowapi import Limiter
from slowapi.util import get_remote_address
limiter = Limiter(key_func=get_remote_address)


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    remember: bool = Form(False),
    db: Session = Depends(get_db)
):
    """Process login form - rate limited to 5 attempts per minute"""
    # Find user
    user = db.query(User).filter(User.username == username).first()

    if not user or not verify_password(password, user.password_hash):
        # Log failed login attempt
        log_action(
            db=db,
            action=AuditAction.LOGIN_FAILED,
            username=username,
            resource_type=ResourceType.USER,
            details={"reason": "Invalid credentials"},
            request=request,
            success=False
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password",
            "username": username
        })

    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    # Log successful login
    log_action(
        db=db,
        action=AuditAction.LOGIN_SUCCESS,
        user_id=user.id,
        username=user.username,
        resource_type=ResourceType.USER,
        resource_id=user.id,
        request=request
    )

    # Create response with session cookie
    response = RedirectResponse(url="/", status_code=302)
    set_session_cookie(response, user.id, user.username, remember)
    return response


@router.get("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    """Logout and clear session"""
    # Log logout
    current_user = get_current_user(request)
    if current_user:
        log_action(
            db=db,
            action=AuditAction.LOGOUT,
            user_id=current_user.get("user_id"),
            username=current_user.get("username"),
            resource_type=ResourceType.USER,
            request=request
        )

    response = RedirectResponse(url="/login", status_code=302)
    clear_session_cookie(response)
    return response


@router.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request, db: Session = Depends(get_db)):
    """Initial setup page - create admin user"""
    # If users already exist, redirect to login
    user_count = db.query(User).count()
    if user_count > 0:
        return RedirectResponse(url="/login", status_code=302)

    return templates.TemplateResponse("setup.html", {
        "request": request,
        "error": None,
        "username": None
    })


@router.post("/setup", response_class=HTMLResponse)
async def setup_submit(
    request: Request,
    background_tasks: BackgroundTasks,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    subnet: str = Form("192.168.1.0/24"),
    scan_schedule: str = Form("0 2 * * 0"),
    run_scan_now: str = Form("false"),
    db: Session = Depends(get_db)
):
    """Process setup form"""
    # If users already exist, redirect to login
    user_count = db.query(User).count()
    if user_count > 0:
        return RedirectResponse(url="/login", status_code=302)

    # Validate input
    if len(username) < 3:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "error": "Username must be at least 3 characters",
            "username": username
        })

    if len(password) < 8:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "error": "Password must be at least 8 characters",
            "username": username
        })

    if password != confirm_password:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "error": "Passwords do not match",
            "username": username
        })

    # Create user
    user = User(
        username=username,
        password_hash=hash_password(password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info(f"Created admin user: {username}")

    # Save network config from setup wizard
    cfg = get_config()
    cfg.network.subnets = [subnet]
    cfg.network.scan_schedule = scan_schedule
    save_config(cfg)

    # Log setup completion
    log_action(
        db=db,
        action=AuditAction.SETUP_COMPLETE,
        user_id=user.id,
        username=user.username,
        resource_type=ResourceType.USER,
        resource_id=user.id,
        details={"first_user": True},
        request=request
    )

    # Optionally trigger an immediate scan in the background
    if run_scan_now.lower() == "true":
        config = get_config()

        def run_scan():
            from app.database import SessionLocal
            db_session = SessionLocal()
            try:
                scanner = NetworkScanner(db_session)
                scan = scanner.perform_scan(
                    subnet=config.network.subnet,
                    subnets=config.network.subnets,
                    scan_profile=config.network.scan_profile,
                    port_range=config.scanning.port_range,
                    enable_os_detection=config.scanning.enable_os_detection,
                    enable_service_detection=config.scanning.enable_service_detection,
                )
                if scan.status == "completed":
                    detector = ChangeDetector(db_session)
                    detector.detect_changes(scan.id)
            finally:
                db_session.close()

        background_tasks.add_task(run_scan)
        logger.info(f"Setup: triggering initial scan on {config.network.subnets}")

    # Create response with session cookie (auto-login)
    response = RedirectResponse(url="/", status_code=302)
    set_session_cookie(response, user.id, user.username, remember=True)
    return response


@router.get("/api/setup/detect-subnet")
async def detect_subnet():
    """Detect local subnets from network interfaces."""
    import ipaddress
    import socket
    subnets = []

    # Try using netifaces if available, fallback to socket
    try:
        import netifaces
        for iface in netifaces.interfaces():
            if iface.startswith("lo"):
                continue
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                ip = addr.get("addr", "")
                netmask = addr.get("netmask", "")
                if ip and netmask and not ip.startswith("127."):
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        subnets.append({
                            "interface": iface,
                            "ip": ip,
                            "subnet": str(network),
                        })
                    except ValueError:
                        pass
    except ImportError:
        # Fallback: try hostname resolution
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            if not local_ip.startswith("127."):
                # Guess /24
                parts = local_ip.rsplit(".", 1)
                subnets.append({
                    "interface": "eth0",
                    "ip": local_ip,
                    "subnet": parts[0] + ".0/24",
                })
        except Exception:
            pass

    return {"subnets": subnets, "suggested": subnets[0]["subnet"] if subnets else "192.168.1.0/24"}


# API Key Management Endpoints
@router.get("/api/keys", response_model=List[APIKeyResponse])
async def list_api_keys(request: Request, db: Session = Depends(get_db)):
    """List all API keys for the current user"""
    current_user = get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    keys = db.query(APIKey).filter(APIKey.user_id == user.id).order_by(APIKey.created_at.desc()).all()
    return keys


@router.post("/api/keys", response_model=APIKeyCreatedResponse)
async def create_api_key(
    key_data: APIKeyCreateRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Create a new API key. The full key is only shown once!"""
    current_user = get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate the API key
    plain_key = generate_api_key()
    key_hash = hash_api_key(plain_key)
    key_prefix = get_api_key_prefix(plain_key)

    # Calculate expiration if specified
    expires_at = None
    if key_data.expires_in_days:
        from datetime import timedelta
        expires_at = datetime.utcnow() + timedelta(days=key_data.expires_in_days)

    # Create the API key record
    api_key = APIKey(
        user_id=user.id,
        name=key_data.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        expires_at=expires_at
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    logger.info(f"API key '{key_data.name}' created for user {user.username}")

    # Log API key creation
    log_action(
        db=db,
        action=AuditAction.API_KEY_CREATED,
        user_id=user.id,
        username=user.username,
        resource_type=ResourceType.API_KEY,
        resource_id=api_key.id,
        details={"name": key_data.name, "expires_at": expires_at.isoformat() if expires_at else None},
        request=request
    )

    return APIKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        key=plain_key,
        key_prefix=key_prefix,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at
    )


@router.delete("/api/keys/{key_id}")
async def revoke_api_key(
    key_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    """Revoke an API key"""
    current_user = get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    api_key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.user_id == current_user["user_id"]
    ).first()

    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    api_key.is_revoked = True
    db.commit()

    logger.info(f"API key '{api_key.name}' revoked")

    # Log API key revocation
    log_action(
        db=db,
        action=AuditAction.API_KEY_REVOKED,
        user_id=current_user["user_id"],
        username=current_user["username"],
        resource_type=ResourceType.API_KEY,
        resource_id=key_id,
        details={"name": api_key.name},
        request=request
    )

    return {"status": "revoked", "id": key_id, "name": api_key.name}
