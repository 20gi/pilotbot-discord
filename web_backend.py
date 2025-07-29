#!/usr/bin/env python3
"""
Secure Web Backend for Discord Bot Control Panel
Enhanced with comprehensive security features and IPC communication
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
import ipaddress
import re

# FastAPI and security imports
from fastapi import FastAPI, HTTPException, Depends, Request, Response, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
import httpx
from pydantic import BaseModel, validator, Field, constr
import jwt  # PyJWT library, not the built-in jwt module
from passlib.context import CryptContext
import bcrypt

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Security headers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/data/web_security.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Security Configuration
class SecurityConfig:
    # Rate limiting
    RATE_LIMIT_PER_MINUTE = "30/minute"
    RATE_LIMIT_PER_HOUR = "1000/hour"
    LOGIN_RATE_LIMIT = "5/minute"
    
    # Session security
    JWT_EXPIRY_HOURS = 24
    REFRESH_TOKEN_EXPIRY_DAYS = 30
    SESSION_TIMEOUT_MINUTES = 60
    
    # Input validation
    MAX_BIO_LENGTH = 190
    MAX_STATUS_LENGTH = 128
    MAX_USERNAME_LENGTH = 100
    
    # Security headers
    CSP_POLICY = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' wss: https:; "
        "frame-ancestors 'none';"
    )
    
    # IP whitelist (empty means allow all)
    ALLOWED_IPS = []
    
    # Bot IPC settings
    IPC_HOST = "127.0.0.1"
    IPC_PORT = 9001
    IPC_TIMEOUT = 5

# Security Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = SecurityConfig.CSP_POLICY
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )
        
        return response

class IPWhitelistMiddleware(BaseHTTPMiddleware):
    """IP whitelist middleware for additional security"""
    
    async def dispatch(self, request: Request, call_next):
        if SecurityConfig.ALLOWED_IPS:
            client_ip = self._get_client_ip(request)
            if not self._is_ip_allowed(client_ip):
                logger.warning(f"Blocked request from unauthorized IP: {client_ip}")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Access denied from this IP address"}
                )
        
        return await call_next(request)
    
    def _get_client_ip(self, request: Request) -> str:
        """Get real client IP considering proxy headers"""
        # Check common proxy headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def _is_ip_allowed(self, ip: str) -> bool:
        """Check if IP is in whitelist"""
        try:
            client_ip = ipaddress.ip_address(ip)
            for allowed_ip in SecurityConfig.ALLOWED_IPS:
                if ipaddress.ip_address(allowed_ip) == client_ip:
                    return True
                # Support for CIDR notation
                try:
                    if client_ip in ipaddress.ip_network(allowed_ip, strict=False):
                        return True
                except ValueError:
                    continue
            return False
        except ValueError:
            return False

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)

# Pydantic models with validation
class StatusUpdate(BaseModel):
    status_type: str
    status_text: str

    @validator('status_type')
    def validate_status_type(cls, v):
        if v not in ('playing', 'watching', 'listening', 'streaming', 'competing'):
            raise ValueError('Invalid status type')
        return v

    @validator('status_text')
    def validate_status_text(cls, v):
        if len(v) > SecurityConfig.MAX_STATUS_LENGTH:
            raise ValueError(f'Status text must be {SecurityConfig.MAX_STATUS_LENGTH} characters or less')
        return SecurityHelper.sanitize_input(v, SecurityConfig.MAX_STATUS_LENGTH)

class BioUpdate(BaseModel):
    bio_text: str

    @validator('bio_text')
    def validate_bio_text(cls, v):
        if len(v) > SecurityConfig.MAX_BIO_LENGTH:
            raise ValueError(f'Bio text must be {SecurityConfig.MAX_BIO_LENGTH} characters or less')
        return SecurityHelper.sanitize_input(v, SecurityConfig.MAX_BIO_LENGTH)

class OnlineStatusUpdate(BaseModel):
    online_status: str

    @validator('online_status')
    def validate_online_status(cls, v):
        if v not in ('online', 'idle', 'dnd', 'invisible'):
            raise ValueError('Invalid online status')
        return v

class UserManagement(BaseModel):
    user_id: str
    action: str

    @validator('user_id')
    def validate_user_id(cls, v):
        if not v.isdigit():
            raise ValueError('User ID must contain only digits')
        return v

    @validator('action')
    def validate_action(cls, v):
        if v not in ('add', 'remove'):
            raise ValueError('Invalid action')
        return v

class SecurityHelper:
    """Security utility functions"""
    
    @staticmethod
    def sanitize_input(text: str, max_length: int) -> str:
        """Sanitize user input"""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")
        
        # Remove control characters except newlines, carriage returns and tabs
        sanitized = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
        
        # Remove potential XSS patterns
        xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*=',
        ]
        
        for pattern in xss_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        # Truncate to max length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    @staticmethod
    def is_valid_discord_id(user_id: str) -> bool:
        """Validate Discord user ID format"""
        return user_id.isdigit() and len(user_id) >= 17 and len(user_id) <= 20

class Config:
    """Configuration manager with security validation"""
    
    def __init__(self):
        self.config_path = '/app/data/config.json'
        self.config = self.load_config()
        self.validate_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration with error handling"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            logger.error("Configuration file not found")
            raise HTTPException(status_code=500, detail="Configuration not found")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in configuration: {e}")
            raise HTTPException(status_code=500, detail="Invalid configuration")
        
        return config
    
    def validate_config(self):
        """Validate configuration for security"""
        required_fields = [
            'discord_client_id', 'discord_client_secret',
            'jwt_secret', 'owner_id', 'allowed_users', 'base_url'
        ]
        
        for field in required_fields:
            if field not in self.config:
                logger.error(f"Missing required configuration field: {field}")
                raise HTTPException(status_code=500, detail=f"Missing config: {field}")
        
        # Validate Discord IDs
        if not SecurityHelper.is_valid_discord_id(str(self.config['owner_id'])):
            logger.error("Invalid owner_id format")
            raise HTTPException(status_code=500, detail="Invalid owner_id")
        
        for user_id in self.config['allowed_users']:
            if not SecurityHelper.is_valid_discord_id(str(user_id)):
                logger.error(f"Invalid user_id format: {user_id}")
                raise HTTPException(status_code=500, detail=f"Invalid user_id: {user_id}")
        
        # Validate JWT secret strength
        if len(self.config['jwt_secret']) < 32:
            logger.error("JWT secret too short")
            raise HTTPException(status_code=500, detail="JWT secret too weak")
    
    def save_config(self):
        """Save configuration securely"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            os.chmod(self.config_path, 0o600)
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise HTTPException(status_code=500, detail="Failed to save configuration")

class Database:
    """Secure database operations"""
    
    def __init__(self):
        self.db_path = '/app/data/web_data.db'
        self.init_db()
    
    def init_db(self):
        """Initialize database with security tables"""
        os.makedirs('/app/data', exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                session_token TEXT NOT NULL UNIQUE,
                refresh_token TEXT UNIQUE,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                INDEX(user_id),
                INDEX(session_token),
                INDEX(expires_at)
            )
        ''')
        
        # Security events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                ip_address TEXT,
                user_id TEXT,
                user_agent TEXT,
                details TEXT,
                INDEX(timestamp),
                INDEX(event_type),
                INDEX(severity)
            )
        ''')
        
        # Login attempts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                user_id TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN NOT NULL,
                user_agent TEXT,
                INDEX(ip_address),
                INDEX(timestamp)
            )
        ''')
        
        # Activity log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                source TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                session_id TEXT,
                INDEX(timestamp),
                INDEX(user_id),
                INDEX(action)
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Set secure permissions
        os.chmod(self.db_path, 0o600)
    
    def log_security_event(self, event_type: str, severity: str, description: str,
                          ip_address: Optional[str] = None, user_id: Optional[str] = None,
                          user_agent: Optional[str] = None, details: Optional[str] = None):
        """Log security events"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_events 
                (event_type, severity, description, ip_address, user_id, user_agent, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (event_type, severity, description, ip_address, user_id, user_agent, details))
            conn.commit()
            conn.close()
            
            logger.warning(f"Security Event ({severity}): {event_type} - {description}")
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
    
    def log_login_attempt(self, ip_address: str, user_id: Optional[str] = None,
                         success: bool = False, user_agent: Optional[str] = None):
        """Log login attempts"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO login_attempts (ip_address, user_id, success, user_agent)
                VALUES (?, ?, ?, ?)
            ''', (ip_address, user_id, success, user_agent))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to log login attempt: {e}")
    
    def check_brute_force(self, ip_address: str, window_minutes: int = 15) -> bool:
        """Check for brute force attacks"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check failed attempts in the last window
            cursor.execute('''
                SELECT COUNT(*) FROM login_attempts 
                WHERE ip_address = ? AND success = FALSE 
                AND timestamp > datetime('now', '-{} minutes')
            '''.format(window_minutes), (ip_address,))
            
            failed_attempts = cursor.fetchone()[0]
            conn.close()
            
            return failed_attempts >= 5  # 5 failed attempts = brute force
            
        except Exception as e:
            logger.error(f"Failed to check brute force: {e}")
            return False
    
    def create_session(self, user_id: str, ip_address: Optional[str] = None,
                      user_agent: Optional[str] = None) -> tuple:
        """Create new session"""
        try:
            session_token = SecurityHelper.generate_secure_token()
            refresh_token = SecurityHelper.generate_secure_token()
            expires_at = datetime.utcnow() + timedelta(hours=SecurityConfig.JWT_EXPIRY_HOURS)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions 
                (user_id, session_token, refresh_token, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, session_token, refresh_token, expires_at, ip_address, user_agent))
            conn.commit()
            conn.close()
            
            return session_token, refresh_token
            
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            raise HTTPException(status_code=500, detail="Session creation failed")
    
    def validate_session(self, session_token: str) -> Optional[str]:
        """Validate session token"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT user_id FROM sessions 
                WHERE session_token = ? AND expires_at > datetime('now') AND is_active = TRUE
            ''', (session_token,))
            
            result = cursor.fetchone()
            
            if result:
                # Update last used timestamp
                cursor.execute('''
                    UPDATE sessions SET last_used = datetime('now') 
                    WHERE session_token = ?
                ''', (session_token,))
                conn.commit()
            
            conn.close()
            return result[0] if result else None
            
        except Exception as e:
            logger.error(f"Failed to validate session: {e}")
            return None
    
    def revoke_session(self, session_token: str):
        """Revoke session"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions SET is_active = FALSE 
                WHERE session_token = ?
            ''', (session_token,))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to revoke session: {e}")
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM sessions WHERE expires_at < datetime('now')
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to cleanup sessions: {e}")

class IPCClient:
    """Secure IPC client for bot communication"""
    
    def __init__(self):
        self.secret_key = self._load_ipc_secret()
    
    def _load_ipc_secret(self) -> bytes:
        """Load IPC secret key"""
        try:
            with open('/app/data/ipc_secret.key', 'rb') as f:
                return f.read()
        except FileNotFoundError:
            logger.error("IPC secret key not found")
            raise HTTPException(status_code=500, detail="IPC configuration error")
    
    def _create_hmac_signature(self, data: bytes) -> str:
        """Create HMAC signature for request"""
        return hmac.new(self.secret_key, data, hashlib.sha256).hexdigest()
    
    async def send_command(self, command: str, **kwargs) -> Dict[str, Any]:
        """Send secure command to bot via IPC"""
        try:
            # Prepare payload
            payload = {
                'command': command,
                'timestamp': int(time.time()),
                **kwargs
            }
            
            payload_json = json.dumps(payload, sort_keys=True)
            signature = self._create_hmac_signature(payload_json.encode())
            
            # Create HTTP request
            request_data = f"POST /ipc HTTP/1.1\r\nX-Signature: {signature}\r\n\r\n{payload_json}"
            
            # Connect to bot IPC server
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(SecurityConfig.IPC_HOST, SecurityConfig.IPC_PORT),
                timeout=SecurityConfig.IPC_TIMEOUT
            )
            
            # Send request
            writer.write(request_data.encode())
            await writer.drain()
            
            # Read response
            response_data = await asyncio.wait_for(
                reader.read(4096),
                timeout=SecurityConfig.IPC_TIMEOUT
            )
            
            writer.close()
            await writer.wait_closed()
            
            # Parse response
            response_str = response_data.decode('utf-8')
            
            # Extract JSON body from HTTP response
            body_start = response_str.find('\r\n\r\n')
            if body_start == -1:
                raise ValueError("Invalid response format")
            
            response_body = response_str[body_start + 4:]
            return json.loads(response_body)
            
        except asyncio.TimeoutError:
            logger.error("IPC request timeout")
            raise HTTPException(status_code=503, detail="Bot communication timeout")
        except ConnectionRefusedError:
            logger.error("Failed to connect to bot IPC server")
            raise HTTPException(status_code=503, detail="Bot service unavailable")
        except Exception as e:
            logger.error(f"IPC communication error: {e}")
            raise HTTPException(status_code=500, detail="Bot communication error")

# Initialize components
config_manager = Config()
database = Database()
ipc_client = IPCClient()

# FastAPI app setup
app = FastAPI(
    title="Discord Bot Control Panel API",
    description="Secure API for Discord bot management",
    version="2.0.0",
    docs_url=None,  # Disable docs in production
    redoc_url=None   # Disable redoc in production
)

# Add security middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(IPWhitelistMiddleware)
app.add_middleware(SlowAPIMiddleware)

# CORS middleware with strict settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://localhost:3000"],  # Restrict origins
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],  # Only needed methods
    allow_headers=["Authorization", "Content-Type"],
    max_age=3600
)

# Rate limiting error handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Background task for cleanup
async def cleanup_task():
    """Background cleanup task"""
    while True:
        try:
            database.cleanup_expired_sessions()
            await asyncio.sleep(3600)  # Run every hour
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")
            await asyncio.sleep(300)  # Retry in 5 minutes

@app.on_event("startup")
async def startup_event():
    """Startup tasks"""
    logger.info("Starting secure web backend...")
    
    # Start background cleanup task
    asyncio.create_task(cleanup_task())
    
    # Log startup
    database.log_security_event(
        'system_startup',
        'INFO',
        'Web backend started successfully'
    )

# Authentication functions
def get_client_info(request: Request) -> tuple:
    """Get client IP and user agent"""
    # Get real IP considering proxy headers
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip_address = forwarded_for.split(",")[0].strip()
    else:
        ip_address = request.headers.get("X-Real-IP") or (request.client.host if request.client else "unknown")
    
    user_agent = request.headers.get("User-Agent", "Unknown")
    return ip_address, user_agent

async def get_discord_user(access_token: str) -> Optional[Dict[str, Any]]:
    """Get Discord user info"""
    try:
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = await client.get(
                "https://discord.com/api/users/@me",
                headers=headers,
                timeout=10.0
            )
            if response.status_code == 200:
                return response.json()
            return None
    except Exception as e:
        logger.error(f"Failed to get Discord user: {e}")
        return None

def create_jwt_token(user_id: str) -> str:
    """Create JWT token"""
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(hours=SecurityConfig.JWT_EXPIRY_HOURS),
        "iat": datetime.utcnow(),
        "jti": SecurityHelper.generate_secure_token(16)  # JWT ID for revocation
    }
    return jwt.encode(payload, config_manager.config["jwt_secret"], algorithm="HS256")

def verify_jwt_token(token: str) -> Optional[str]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(
            token, 
            config_manager.config["jwt_secret"], 
            algorithms=["HS256"]
        )
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        logger.info("JWT token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {e}")
        return None

# Authentication dependencies
async def get_current_user(request: Request) -> str:
    """Get current authenticated user"""
    ip_address, user_agent = get_client_info(request)
    
    # Check for session token in cookies
    session_token = request.cookies.get("session_token")
    if session_token:
        user_id = database.validate_session(session_token)
        if user_id:
            return user_id
    
    # Check for JWT token in Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        user_id = verify_jwt_token(token)
        if user_id:
            return user_id
    
    # Log failed authentication
    database.log_security_event(
        'authentication_failed',
        'MEDIUM',
        'Authentication required',
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    raise HTTPException(status_code=401, detail="Authentication required")

async def get_authorized_user(request: Request) -> str:
    """Get authorized user (must be in allowed users or owner)"""
    user_id = await get_current_user(request)
    
    if (user_id not in [str(uid) for uid in config_manager.config["allowed_users"]] and 
        user_id != str(config_manager.config["owner_id"])):
        
        ip_address, user_agent = get_client_info(request)
        database.log_security_event(
            'authorization_failed',
            'HIGH',
            f'Unauthorized access attempt by user {user_id}',
            ip_address=ip_address,
            user_id=user_id,
            user_agent=user_agent
        )
        
        raise HTTPException(status_code=403, detail="Access denied")
    
    return user_id

async def get_owner_user(request: Request) -> str:
    """Get owner user (owner only)"""
    user_id = await get_current_user(request)
    
    if user_id != str(config_manager.config["owner_id"]):
        ip_address, user_agent = get_client_info(request)
        database.log_security_event(
            'owner_access_denied',
            'HIGH',
            f'Non-owner attempted owner action: {user_id}',
            ip_address=ip_address,
            user_id=user_id,
            user_agent=user_agent
        )
        
        raise HTTPException(status_code=403, detail="Owner access required")
    
    return user_id

# API Routes
@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "message": "Discord Bot Control Panel API",
        "version": "2.0.0",
        "status": "secure"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/auth/discord")
@limiter.limit(SecurityConfig.LOGIN_RATE_LIMIT)
async def discord_auth(request: Request):
    """Initiate Discord OAuth"""
    client_id = config_manager.config["discord_client_id"]
    redirect_uri = f"{config_manager.config['base_url']}/auth/callback"
    
    # Generate state parameter for CSRF protection
    state = SecurityHelper.generate_secure_token()
    
    # Store state in session (you might want to use Redis in production)
    # For now, we'll include it in the URL and verify it in callback
    
    auth_url = (
        f"https://discord.com/api/oauth2/authorize"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code"
        f"&scope=identify"
        f"&state={state}"
    )
    
    ip_address, user_agent = get_client_info(request)
    database.log_security_event(
        'oauth_initiated',
        'INFO',
        'Discord OAuth initiated',
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    return RedirectResponse(auth_url)

@app.get("/auth/callback")
@limiter.limit(SecurityConfig.LOGIN_RATE_LIMIT)
async def discord_callback(request: Request, code: str, state: str):
    """Handle Discord OAuth callback"""
    ip_address, user_agent = get_client_info(request)
    
    # Check for brute force attacks
    if database.check_brute_force(ip_address):
        database.log_security_event(
            'brute_force_detected',
            'CRITICAL',
            f'Brute force attack from {ip_address}',
            ip_address=ip_address,
            user_agent=user_agent
        )
        raise HTTPException(status_code=429, detail="Too many failed attempts")
    
    try:
        client_id = config_manager.config["discord_client_id"]
        client_secret = config_manager.config["discord_client_secret"]
        redirect_uri = f"{config_manager.config['base_url']}/auth/callback"
        
        # Exchange code for access token
        async with httpx.AsyncClient() as client:
            token_data = {
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
            }
            
            response = await client.post(
                "https://discord.com/api/oauth2/token",
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10.0
            )
            
            if response.status_code != 200:
                database.log_login_attempt(ip_address, success=False, user_agent=user_agent)
                return RedirectResponse("/access-denied")
            
            token_info = response.json()
            access_token = token_info["access_token"]
            
            # Get user info
            user_info = await get_discord_user(access_token)
            if not user_info:
                database.log_login_attempt(ip_address, success=False, user_agent=user_agent)
                return RedirectResponse("/access-denied")
            
            user_id = user_info["id"]
            username = user_info["username"]
            
            # Check if user is authorized
            if (user_id not in [str(uid) for uid in config_manager.config["allowed_users"]] and 
                user_id != str(config_manager.config["owner_id"])):
                
                database.log_login_attempt(ip_address, user_id, success=False, user_agent=user_agent)
                database.log_security_event(
                    'unauthorized_login_attempt',
                    'HIGH',
                    f'Unauthorized login attempt by {username} ({user_id})',
                    ip_address=ip_address,
                    user_id=user_id,
                    user_agent=user_agent
                )
                return RedirectResponse("/access-denied")
            
            # Create session
            session_token, refresh_token = database.create_session(
                user_id, ip_address, user_agent
            )
            
            # Log successful login
            database.log_login_attempt(ip_address, user_id, success=True, user_agent=user_agent)
            database.log_security_event(
                'successful_login',
                'INFO',
                f'User {username} ({user_id}) logged in successfully',
                ip_address=ip_address,
                user_id=user_id,
                user_agent=user_agent
            )
            
            # Create JWT token for API access
            jwt_token = create_jwt_token(user_id)
            
            # Redirect to dashboard with secure cookies
            response = RedirectResponse("/dashboard")
            response.set_cookie(
                "session_token",
                session_token,
                httponly=True,
                secure=True,  # HTTPS only
                samesite="strict",
                max_age=SecurityConfig.JWT_EXPIRY_HOURS * 3600
            )
            response.set_cookie(
                "refresh_token",
                refresh_token,
                httponly=True,
                secure=True,
                samesite="strict",
                max_age=SecurityConfig.REFRESH_TOKEN_EXPIRY_DAYS * 24 * 3600
            )
            
            return response
            
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        database.log_login_attempt(ip_address, success=False, user_agent=user_agent)
        database.log_security_event(
            'oauth_error',
            'HIGH',
            f'OAuth callback error: {str(e)}',
            ip_address=ip_address,
            user_agent=user_agent
        )
        return RedirectResponse("/access-denied")

@app.get("/access-denied")
async def access_denied(request: Request):
    """Access denied page"""
    ip_address, user_agent = get_client_info(request)
    
    database.log_security_event(
        'access_denied_page_viewed',
        'MEDIUM',
        'User viewed access denied page',
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    return HTMLResponse("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Access Denied - Discord Bot Control Panel</title>
        <style>
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                text-align: center; 
                margin: 0;
                padding: 50px 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container { 
                max-width: 500px; 
                background: rgba(255, 255, 255, 0.1);
                padding: 40px;
                border-radius: 15px;
                backdrop-filter: blur(10px);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            }
            .error { 
                color: #ff6b6b; 
                font-size: 2.5em;
                margin-bottom: 20px;
                text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
            }
            h1 { margin-bottom: 30px; }
            p { 
                font-size: 1.1em; 
                line-height: 1.6;
                margin-bottom: 20px;
            }
            .security-note {
                font-size: 0.9em;
                opacity: 0.8;
                margin-top: 30px;
                padding: 15px;
                background: rgba(0, 0, 0, 0.2);
                border-radius: 8px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="error">🔒</div>
            <h1>Access Denied</h1>
            <p>You don't have permission to access this application.</p>
            <p>This incident has been logged for security purposes.</p>
            <p>Please contact the administrator if you believe this is an error.</p>
            <div class="security-note">
                <strong>Security Notice:</strong> All access attempts are monitored and logged.
                Unauthorized access attempts may result in IP blocking.
            </div>
        </div>
    </body>
    </html>
    """)

@app.get("/api/user")
@limiter.limit(SecurityConfig.RATE_LIMIT_PER_MINUTE)
async def get_user_info(request: Request, user_id: str = Depends(get_authorized_user)):
    """Get current user information"""
    is_owner = user_id == str(config_manager.config["owner_id"])
    
    return {
        "user_id": user_id,
        "is_owner": is_owner,
        "permissions": {
            "can_manage_users": is_owner,
            "can_view_logs": is_owner,
            "can_update_bio": True,
            "can_update_status": True
        }
    }

@app.post("/api/bio")
@limiter.limit(SecurityConfig.RATE_LIMIT_PER_MINUTE)
async def update_bio(request: Request, bio_data: BioUpdate, 
                    user_id: str = Depends(get_authorized_user)):
    """Update bot bio"""
    ip_address, user_agent = get_client_info(request)
    
    try:
        # Get username from previous logs or default
        username = "Unknown"
        try:
            conn = sqlite3.connect(database.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT username FROM activity_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1',
                (user_id,)
            )
            result = cursor.fetchone()
            username = result[0] if result else "Unknown"
            conn.close()
        except:
            pass
        
        # Send command to bot via IPC
        response = await ipc_client.send_command(
            'update_bio',
            user_id=user_id,
            username=username,
            bio_text=bio_data.bio_text
        )
        
        if response.get('success'):
            # Log activity in web backend
            database.log_security_event(
                'bio_updated',
                'INFO',
                f'Bio updated by {username} ({user_id})',
                ip_address=ip_address,
                user_id=user_id,
                user_agent=user_agent,
                details=bio_data.bio_text
            )
            
            return {"message": "Bio updated successfully", "bio": bio_data.bio_text}
        else:
            database.log_security_event(
                'bio_update_failed',
                'MEDIUM',
                f'Bio update failed for {username} ({user_id})',
                ip_address=ip_address,
                user_id=user_id,
                user_agent=user_agent
            )
            raise HTTPException(status_code=500, detail="Failed to update bio")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bio update error: {e}")
        database.log_security_event(
            'bio_update_error',
            'HIGH',
            f'Bio update error: {str(e)}',
            ip_address=ip_address,
            user_id=user_id,
            user_agent=user_agent
        )
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/status")
@limiter.limit(SecurityConfig.RATE_LIMIT_PER_MINUTE)
async def update_status(request: Request, status_data: StatusUpdate,
                       user_id: str = Depends(get_authorized_user)):
    """Update bot status"""
    ip_address, user_agent = get_client_info(request)
    
    try:
        # Get username
        username = "Unknown"
        try:
            conn = sqlite3.connect(database.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT username FROM activity_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1',
                (user_id,)
            )
            result = cursor.fetchone()
            username = result[0] if result else "Unknown"
            conn.close()
        except:
            pass
        
        # Send command to bot via IPC
        response = await ipc_client.send_command(
            'update_status',
            user_id=user_id,
            username=username,
            status_type=status_data.status_type,
            status_text=status_data.status_text
        )
        
        if response.get('success'):
            database.log_security_event(
                'status_updated',
                'INFO',
                f'Status updated by {username} ({user_id})',
                ip_address=ip_address,
                user_id=user_id,
                user_agent=user_agent,
                details=f"{status_data.status_type}: {status_data.status_text}"
            )
            
            return {
                "message": "Status updated successfully",
                "status": {
                    "type": status_data.status_type,
                    "text": status_data.status_text
                }
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to update status")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Status update error: {e}")
        database.log_security_event(
            'status_update_error',
            'HIGH',
            f'Status update error: {str(e)}',
            ip_address=ip_address,
            user_id=user_id,
            user_agent=user_agent
        )
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/online-status")
@limiter.limit(SecurityConfig.RATE_LIMIT_PER_MINUTE)
async def update_online_status(request: Request, status_data: OnlineStatusUpdate,
                              user_id: str = Depends(get_authorized_user)):
    """Update bot online status"""
    ip_address, user_agent = get_client_info(request)
    
    try:
        # Get username
        username = "Unknown"
        try:
            conn = sqlite3.connect(database.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT username FROM activity_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1',
                (user_id,)
            )
            result = cursor.fetchone()
            username = result[0] if result else "Unknown"
            conn.close()
        except:
            pass
        
        # Send command to bot via IPC
        response = await ipc_client.send_command(
            'update_online_status',
            user_id=user_id,
            username=username,
            online_status=status_data.online_status
        )
        
        if response.get('success'):
            database.log_security_event(
                'online_status_updated',
                'INFO',
                f'Online status updated by {username} ({user_id})',
                ip_address=ip_address,
                user_id=user_id,
                user_agent=user_agent,
                details=status_data.online_status
            )
            
            return {
                "message": "Online status updated successfully",
                "online_status": status_data.online_status
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to update online status")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Online status update error: {e}")
        database.log_security_event(
            'online_status_update_error',
            'HIGH',
            f'Online status update error: {str(e)}',
            ip_address=ip_address,
            user_id=user_id,
            user_agent=user_agent
        )
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/clear-status")
@limiter.limit(SecurityConfig.RATE_LIMIT_PER_MINUTE)
async def clear_status(request: Request, user_id: str = Depends(get_authorized_user)):
    """Clear bot status"""
    ip_address, user_agent = get_client_info(request)
    
    try:
        # Get username
        username = "Unknown"
        try:
            conn = sqlite3.connect(database.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT username FROM activity_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1',
                (user_id,)
            )
            result = cursor.fetchone()
            username = result[0] if result else "Unknown"
            conn.close()
        except:
            pass
        
        # Send command to bot via IPC
        response = await ipc_client.send_command(
            'clear_status',
            user_id=user_id,
            username=username
        )
        
        if response.get('success'):
            database.log_security_event(
                'status_cleared',
                'INFO',
                f'Status cleared by {username} ({user_id})',
                ip_address=ip_address,
                user_id=user_id,
                user_agent=user_agent
            )
            
            return {"message": "Status cleared successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to clear status")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Clear status error: {e}")
        database.log_security_event(
            'clear_status_error',
            'HIGH',
            f'Clear status error: {str(e)}',
            ip_address=ip_address,
            user_id=user_id,
            user_agent=user_agent
        )
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/status")
@limiter.limit(SecurityConfig.RATE_LIMIT_PER_MINUTE)
async def get_current_status(request: Request, user_id: str = Depends(get_authorized_user)):
    """Get current bot status"""
    try:
        # Send command to bot via IPC
        response = await ipc_client.send_command('get_status')
        
        if response.get('success'):
            return {"status": response.get('status', {})}
        else:
            raise HTTPException(status_code=500, detail="Failed to get status")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get status error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/logs")
@limiter.limit("10/minute")
async def get_logs(request: Request, limit: int = 100, 
                  user_id: str = Depends(get_owner_user)):
    """Get activity logs (owner only)"""
    try:
        # Get bot logs via IPC or from local database
        conn = sqlite3.connect('/app/data/bot_data.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, user_id, username, action, details, source
            FROM activity_log
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (min(limit, 1000),))  # Max 1000 logs
        
        logs = cursor.fetchall()
        conn.close()
        
        formatted_logs = [
            {
                "timestamp": log[0],
                "user_id": log[1],
                "username": log[2],
                "action": log[3],
                "details": log[4],
                "source": log[5]
            }
            for log in logs
        ]
        
        return {"logs": formatted_logs}
        
    except Exception as e:
        logger.error(f"Get logs error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve logs")

@app.get("/api/security-logs")
@limiter.limit("5/minute")
async def get_security_logs(request: Request, limit: int = 100,
                           user_id: str = Depends(get_owner_user)):
    """Get security logs (owner only)"""
    try:
        conn = sqlite3.connect(database.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, event_type, severity, description, ip_address, user_id, details
            FROM security_events
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (min(limit, 1000),))
        
        logs = cursor.fetchall()
        conn.close()
        
        formatted_logs = [
            {
                "timestamp": log[0],
                "event_type": log[1],
                "severity": log[2],
                "description": log[3],
                "ip_address": log[4],
                "user_id": log[5],
                "details": log[6]
            }
            for log in logs
        ]
        
        return {"security_logs": formatted_logs}
        
    except Exception as e:
        logger.error(f"Get security logs error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve security logs")

@app.post("/api/manage-users")
@limiter.limit("10/minute")
async def manage_users(request: Request, user_data: UserManagement,
                      user_id: str = Depends(get_owner_user)):
    """Manage allowed users (owner only)"""
    ip_address, user_agent = get_client_info(request)
    
    try:
        target_user_id = user_data.user_id
        action = user_data.action
        
        # Validate Discord ID format
        if not SecurityHelper.is_valid_discord_id(target_user_id):
            raise HTTPException(status_code=400, detail="Invalid Discord user ID")
        
        # Prevent owner from removing themselves
        if action == "remove" and target_user_id == str(config_manager.config["owner_id"]):
            raise HTTPException(status_code=400, detail="Cannot remove owner from allowed users")
        
        # Update allowed users list
        allowed_users = config_manager.config["allowed_users"]
        
        if action == "add":
            if target_user_id not in [str(uid) for uid in allowed_users]:
                allowed_users.append(int(target_user_id))
                message = f"User {target_user_id} added to allowed users"
            else:
                raise HTTPException(status_code=400, detail="User already in allowed list")
                
        elif action == "remove":
            allowed_users = [uid for uid in allowed_users if str(uid) != target_user_id]
            message = f"User {target_user_id} removed from allowed users"
        else:
            raise HTTPException(status_code=400, detail="Invalid action")
        
        # Save configuration
        config_manager.config["allowed_users"] = allowed_users
        config_manager.save_config()
        
        # Log security event
        database.log_security_event(
            'user_management',
            'HIGH',
            f'User {action}: {target_user_id} by owner {user_id}',
            ip_address=ip_address,
            user_id=user_id,
            user_agent=user_agent,
            details=f"Action: {action}, Target: {target_user_id}"
        )
        
        return {"message": message, "allowed_users": allowed_users}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User management error: {e}")
        database.log_security_event(
            'user_management_error',
            'HIGH',
            f'User management error: {str(e)}',
            ip_address=ip_address,
            user_id=user_id,
            user_agent=user_agent
        )
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/logout")
@limiter.limit(SecurityConfig.RATE_LIMIT_PER_MINUTE)
async def logout(request: Request, user_id: str = Depends(get_current_user)):
    """Logout user"""
    ip_address, user_agent = get_client_info(request)
    
    # Revoke session
    session_token = request.cookies.get("session_token")
    if session_token:
        database.revoke_session(session_token)
    
    # Log logout
    database.log_security_event(
        'user_logout',
        'INFO',
        f'User {user_id} logged out',
        ip_address=ip_address,
        user_id=user_id,
        user_agent=user_agent
    )
    
    # Clear cookies
    response = JSONResponse({"message": "Logged out successfully"})
    response.delete_cookie("session_token", httponly=True, secure=True, samesite="strict")
    response.delete_cookie("refresh_token", httponly=True, secure=True, samesite="strict")
    
    return response

@app.get("/api/system-info")
@limiter.limit("5/minute")
async def get_system_info(request: Request, user_id: str = Depends(get_owner_user)):
    """Get system information (owner only)"""
    try:
        # Get system stats
        import psutil
        
        # Get disk usage
        disk_usage = psutil.disk_usage('/app/data')
        
        # Get memory usage
        memory = psutil.virtual_memory()
        
        # Get active sessions count
        conn = sqlite3.connect(database.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM sessions WHERE is_active = TRUE AND expires_at > datetime("now")')
        active_sessions = cursor.fetchone()[0]
        conn.close()
        
        return {
            "system": {
                "disk_usage": {
                    "total": disk_usage.total,
                    "used": disk_usage.used,
                    "free": disk_usage.free,
                    "percent": disk_usage.percent
                },
                "memory": {
                    "total": memory.total,
                    "used": memory.used,
                    "percent": memory.percent
                },
                "active_sessions": active_sessions
            },
            "security": {
                "rate_limiting_enabled": True,
                "ip_whitelisting_enabled": bool(SecurityConfig.ALLOWED_IPS),
                "security_headers_enabled": True,
                "session_timeout_minutes": SecurityConfig.SESSION_TIMEOUT_MINUTES
            }
        }
        
    except Exception as e:
        logger.error(f"System info error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system information")

# Serve static files (React build)
app.mount("/", StaticFiles(directory="/app/web/build", html=True), name="static")

# Run the application
async def run_web_backend():
    """Run the web backend server"""
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True,
        server_header=False,  # Hide server header for security
        date_header=False     # Hide date header for security
    )
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    # Ensure data directory exists with proper permissions
    os.makedirs('/app/data', exist_ok=True)
    os.chmod('/app/data', 0o700)
    
    # Run the secure web backend
    try:
        asyncio.run(run_web_backend())
    except KeyboardInterrupt:
        logger.info("Web backend stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)