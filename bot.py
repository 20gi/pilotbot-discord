#!/usr/bin/env python3
"""
Secure Discord Bot with IPC Communication
Enhanced with comprehensive security features
"""

import discord
from discord import app_commands
from discord.ext import commands
import aiohttp
import asyncio
import json
import sqlite3
import logging
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager
import os
import signal
import sys
from pathlib import Path

# Security imports
import bcrypt
from cryptography.fernet import Fernet
import hmac

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/data/bot_security.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Security Configuration
class SecurityConfig:
    MAX_BIO_LENGTH = 190  # Discord limit
    MAX_STATUS_LENGTH = 128
    RATE_LIMIT_WINDOW = 60  # seconds
    MAX_REQUESTS_PER_WINDOW = 10
    ALLOWED_STATUS_TYPES = ['playing', 'watching', 'listening', 'streaming', 'competing']
    ALLOWED_ONLINE_STATUSES = ['online', 'idle', 'dnd', 'invisible']
    IPC_SECRET_LENGTH = 32
    SESSION_TIMEOUT = 3600  # 1 hour

class IPCServer:
    """Secure Inter-Process Communication Server"""
    
    def __init__(self, bot_instance):
        self.bot = bot_instance
        self.server = None
        self.secret_key = self._generate_ipc_secret()
        self.rate_limiter = {}
        self.active_sessions = {}
        
    def _generate_ipc_secret(self) -> bytes:
        """Generate secure IPC secret key"""
        secret = secrets.token_bytes(SecurityConfig.IPC_SECRET_LENGTH)
        # Store in secure location
        with open('/app/data/ipc_secret.key', 'wb') as f:
            f.write(secret)
        os.chmod('/app/data/ipc_secret.key', 0o600)
        return secret
    
    def _verify_hmac_signature(self, data: bytes, signature: str) -> bool:
        """Verify HMAC signature for request authentication"""
        try:
            expected = hmac.new(self.secret_key, data, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature)
        except Exception as e:
            logger.error(f"HMAC verification failed: {e}")
            return False
    
    def _rate_limit_check(self, client_id: str) -> bool:
        """Check rate limiting for client"""
        now = time.time()
        window_start = now - SecurityConfig.RATE_LIMIT_WINDOW
        
        if client_id not in self.rate_limiter:
            self.rate_limiter[client_id] = []
        
        # Clean old requests
        self.rate_limiter[client_id] = [
            req_time for req_time in self.rate_limiter[client_id] 
            if req_time > window_start
        ]
        
        # Check limit
        if len(self.rate_limiter[client_id]) >= SecurityConfig.MAX_REQUESTS_PER_WINDOW:
            logger.warning(f"Rate limit exceeded for client: {client_id}")
            return False
        
        self.rate_limiter[client_id].append(now)
        return True
    
    def _sanitize_input(self, text: str, max_length: int) -> str:
        """Sanitize and validate input text"""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")
        
        # Remove potentially dangerous characters
        sanitized = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
        
        # Truncate to max length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()
    
    async def handle_request(self, reader, writer):
        """Handle secure IPC requests"""
        client_addr = writer.get_extra_info('peername')
        client_id = f"{client_addr[0]}:{client_addr[1]}"
        
        try:
            # Rate limiting
            if not self._rate_limit_check(client_id):
                writer.write(b'HTTP/1.1 429 Too Many Requests\r\n\r\n')
                await writer.drain()
                writer.close()
                return
            
            # Read request
            data = await reader.read(8192)  # 8KB limit
            if not data:
                return
            
            try:
                # Parse request
                request_str = data.decode('utf-8')
                lines = request_str.split('\n')
                
                # Extract signature from headers
                signature = None
                for line in lines[1:]:
                    if line.startswith('X-Signature: '):
                        signature = line.split(': ', 1)[1].strip()
                        break
                
                if not signature:
                    raise ValueError("Missing signature")
                
                # Get request body
                body_start = request_str.find('\r\n\r\n')
                if body_start == -1:
                    raise ValueError("Invalid request format")
                
                body = request_str[body_start + 4:]
                
                # Verify signature
                if not self._verify_hmac_signature(body.encode(), signature):
                    raise ValueError("Invalid signature")
                
                # Parse JSON payload
                payload = json.loads(body)
                
                # Process command
                response = await self._process_command(payload, client_id)
                
                # Send response
                response_json = json.dumps(response)
                writer.write(f'HTTP/1.1 200 OK\r\nContent-Length: {len(response_json)}\r\n\r\n{response_json}'.encode())
                
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON from {client_id}")
                writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\nInvalid JSON')
            except ValueError as e:
                logger.error(f"Security violation from {client_id}: {e}")
                writer.write(b'HTTP/1.1 403 Forbidden\r\n\r\nSecurity violation')
            except Exception as e:
                logger.error(f"Error processing request from {client_id}: {e}")
                writer.write(b'HTTP/1.1 500 Internal Server Error\r\n\r\nServer error')
            
            await writer.drain()
            
        except Exception as e:
            logger.error(f"Connection error with {client_id}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def _process_command(self, payload: Dict[str, Any], client_id: str) -> Dict[str, Any]:
        """Process authenticated IPC command"""
        command = payload.get('command')
        user_id = payload.get('user_id')
        username = payload.get('username', 'Unknown')
        
        if not command or not user_id:
            raise ValueError("Missing required fields")
        
        # Log security event
        logger.info(f"IPC Command: {command} from user {user_id} via {client_id}")
        
        # Process command
        if command == 'update_bio':
            bio_text = self._sanitize_input(payload.get('bio_text', ''), SecurityConfig.MAX_BIO_LENGTH)
            success = await self.bot.update_bio(bio_text, user_id, username, 'ipc')
            return {'success': success, 'message': 'Bio updated' if success else 'Bio update failed'}
        
        elif command == 'update_status':
            status_type = payload.get('status_type', '').lower()
            status_text = self._sanitize_input(payload.get('status_text', ''), SecurityConfig.MAX_STATUS_LENGTH)
            
            if status_type not in SecurityConfig.ALLOWED_STATUS_TYPES:
                raise ValueError(f"Invalid status type: {status_type}")
            
            success = await self.bot.update_status(status_type, status_text, user_id, username, 'ipc')
            return {'success': success, 'message': 'Status updated' if success else 'Status update failed'}
        
        elif command == 'update_online_status':
            online_status = payload.get('online_status', '').lower()
            
            if online_status not in SecurityConfig.ALLOWED_ONLINE_STATUSES:
                raise ValueError(f"Invalid online status: {online_status}")
            
            success = await self.bot.update_online_status(online_status, user_id, username, 'ipc')
            return {'success': success, 'message': 'Online status updated' if success else 'Online status update failed'}
        
        elif command == 'clear_status':
            success = await self.bot.clear_status(user_id, username, 'ipc')
            return {'success': success, 'message': 'Status cleared' if success else 'Status clear failed'}
        
        elif command == 'get_status':
            status = await self.bot.get_current_status()
            return {'success': True, 'status': status}
        
        else:
            raise ValueError(f"Unknown command: {command}")
    
    async def start_server(self, host='127.0.0.1', port=9001):
        """Start secure IPC server"""
        try:
            self.server = await asyncio.start_server(
                self.handle_request, host, port
            )
            logger.info(f"IPC Server started on {host}:{port}")
            async with self.server:
                await self.server.serve_forever()
        except Exception as e:
            logger.error(f"IPC Server error: {e}")
            raise

class SecureDiscordBot:
    """Enhanced Discord Bot with Security Features"""
    
    def __init__(self):
        self.config = self._load_config()
        self.db_path = '/app/data/bot_data.db'
        self.setup_intents()
        self.setup_bot()
        self.ipc_server = IPCServer(self)
        self.setup_database()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration with security validation"""
        config_path = '/app/data/config.json'
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            logger.error("Configuration file not found")
            sys.exit(1)
        except json.JSONDecodeError:
            logger.error("Invalid JSON in configuration file")
            sys.exit(1)
        
        # Validate required fields
        required_fields = ['bot_token', 'owner_id', 'allowed_users']
        for field in required_fields:
            if field not in config:
                logger.error(f"Missing required configuration field: {field}")
                sys.exit(1)
        
        return config
    
    def setup_intents(self):
        """Setup Discord intents with minimal permissions"""
        self.intents = discord.Intents.default()
        self.intents.message_content = False  # Don't need message content
        self.intents.guilds = True
        self.intents.guild_messages = False
    
    def setup_bot(self):
        """Setup Discord bot with security configurations"""
        self.bot = commands.Bot(
            command_prefix='!secure_',  # Unique prefix to avoid conflicts
            intents=self.intents,
            help_command=None  # Disable help command for security
        )
        
        # Add event handlers
        self.bot.event(self.on_ready)
        self.bot.event(self.on_error)
        
        # Add slash commands
        self.setup_slash_commands()
    
    def setup_database(self):
        """Initialize secure database"""
        os.makedirs('/app/data', exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Activity log table with enhanced security logging
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
        
        # Security events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                source_ip TEXT,
                user_id TEXT,
                details TEXT,
                INDEX(timestamp),
                INDEX(event_type),
                INDEX(severity)
            )
        ''')
        
        # Rate limiting table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                window_start INTEGER NOT NULL,
                request_count INTEGER DEFAULT 1,
                UNIQUE(identifier, window_start)
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Set secure permissions
        os.chmod(self.db_path, 0o600)
    
    def log_activity(self, user_id: str, username: str, action: str, 
                    details: Optional[str] = None, source: str = "discord", 
                    ip_address: Optional[str] = None, user_agent: Optional[str] = None, 
                    session_id: Optional[str] = None):
        """Log user activity with enhanced security information"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO activity_log 
                (user_id, username, action, details, source, ip_address, user_agent, session_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, username, action, details, source, ip_address, user_agent, session_id))
            conn.commit()
            conn.close()
            
            logger.info(f"Activity logged: {action} by {username} ({user_id}) from {source}")
        except Exception as e:
            logger.error(f"Failed to log activity: {e}")
    
    def log_security_event(self, event_type: str, severity: str, description: str, 
                          source_ip: Optional[str] = None, user_id: Optional[str] = None, details: Optional[str] = None):
        """Log security events"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_events 
                (event_type, severity, description, source_ip, user_id, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (event_type, severity, description, source_ip, user_id, details))
            conn.commit()
            conn.close()
            
            logger.warning(f"Security Event ({severity}): {event_type} - {description}")
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
    
    async def on_ready(self):
        """Bot ready event handler"""
        logger.info(f'{self.bot.user} has connected to Discord!')
        
        # Verify owner ID
        app_info = await self.bot.application_info()
        if app_info.owner.id != int(self.config['owner_id']):
            logger.error("Owner ID mismatch! Potential security issue.")
            await self.bot.close()
            sys.exit(1)
        
        # Sync slash commands if control server is configured
        control_server_id = self.config.get('control_server_id')
        if control_server_id:
            try:
                control_guild = discord.Object(id=control_server_id)
                await self.bot.tree.sync(guild=control_guild)
                logger.info(f"Synced slash commands for guild: {control_server_id}")
            except Exception as e:
                logger.error(f"Failed to sync commands: {e}")
    
    async def on_error(self, event, *args, **kwargs):
        """Global error handler"""
        logger.error(f"Discord error in {event}: {args}, {kwargs}")
    
    def setup_slash_commands(self):
        """Setup secure slash commands"""
        
        def is_owner_and_in_control_channel():
            async def predicate(interaction: discord.Interaction) -> bool:
                # Verify owner
                if interaction.user.id != int(self.config['owner_id']):
                    self.log_security_event(
                        'unauthorized_command_access',
                        'HIGH',
                        f'Non-owner attempted to use owner command: {interaction.user.id}',
                        user_id=str(interaction.user.id)
                    )
                    raise app_commands.CheckFailure("Access denied")
                
                # Verify control channel if configured
                control_channel_id = self.config.get('control_channel_id')
                if control_channel_id and interaction.channel_id != control_channel_id:
                    self.log_security_event(
                        'wrong_channel_command',
                        'MEDIUM',
                        f'Command used in wrong channel: {interaction.channel_id}',
                        user_id=str(interaction.user.id)
                    )
                    raise app_commands.CheckFailure("Wrong channel")
                
                return True
            return app_commands.check(predicate)
        
        @self.bot.tree.command(name='updatebio', description='Update the bot bio (Owner only)')
        @is_owner_and_in_control_channel()
        async def update_bio_command(interaction: discord.Interaction, new_bio: str):
            await interaction.response.defer()
            
            try:
                # Sanitize input
                sanitized_bio = self._sanitize_input(new_bio, SecurityConfig.MAX_BIO_LENGTH)
                
                success = await self.update_bio(
                    sanitized_bio,
                    str(interaction.user.id),
                    interaction.user.display_name,
                    "discord_slash"
                )
                
                if success:
                    await interaction.followup.send(f"✅ Bio updated to: {sanitized_bio}")
                else:
                    await interaction.followup.send("❌ Failed to update bio")
                    
            except Exception as e:
                logger.error(f"Bio update command error: {e}")
                await interaction.followup.send("❌ An error occurred")
        
        @self.bot.tree.command(name='status', description='Update bot status (Owner only)')
        @is_owner_and_in_control_channel()
        async def update_status_command(interaction: discord.Interaction, 
                                      status_type: str, status_text: str):
            await interaction.response.defer()
            
            try:
                # Validate and sanitize
                status_type = status_type.lower()
                if status_type not in SecurityConfig.ALLOWED_STATUS_TYPES:
                    await interaction.followup.send(f"❌ Invalid status type. Use: {', '.join(SecurityConfig.ALLOWED_STATUS_TYPES)}")
                    return
                
                sanitized_text = self._sanitize_input(status_text, SecurityConfig.MAX_STATUS_LENGTH)
                
                success = await self.update_status(
                    status_type,
                    sanitized_text,
                    str(interaction.user.id),
                    interaction.user.display_name,
                    "discord_slash"
                )
                
                if success:
                    await interaction.followup.send(f"✅ Status updated: {status_type} {sanitized_text}")
                else:
                    await interaction.followup.send("❌ Failed to update status")
                    
            except Exception as e:
                logger.error(f"Status update command error: {e}")
                await interaction.followup.send("❌ An error occurred")
    
    def _sanitize_input(self, text: str, max_length: int) -> str:
        """Sanitize user input"""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")
        
        # Remove control characters except newlines, carriage returns, and tabs
        sanitized = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
        
        # Truncate to max length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()
    
    async def update_bio(self, bio_text: str, user_id: Optional[str] = None, 
                        username: str = "Unknown", source: str = "unknown") -> bool:
        """Update bot bio with security logging"""
        try:
            url = "https://discord.com/api/v10/users/@me"
            headers = {
                "Authorization": f"Bot {self.bot.http.token}",
                "Content-Type": "application/json"
            }
            data = {"bio": bio_text}
            
            async with aiohttp.ClientSession() as session:
                async with session.patch(url, json=data, headers=headers) as response:
                    if response.status == 200:
                        logger.info(f"Bio updated successfully to: {bio_text}")
                        if user_id:
                            self.log_activity(user_id, username, "Bio Update", bio_text, source)
                        return True
                    else:
                        logger.error(f"Failed to update bio: {response.status}")
                        if user_id:
                            self.log_security_event(
                                'bio_update_failed',
                                'MEDIUM',
                                f'Bio update failed with status {response.status}',
                                user_id=user_id
                            )
                        return False
                        
        except Exception as e:
            logger.error(f"Bio update error: {e}")
            if user_id:
                self.log_security_event(
                    'bio_update_error',
                    'HIGH',
                    f'Bio update error: {str(e)}',
                    user_id=user_id
                )
            return False
    
    async def update_status(self, status_type: str, status_text: str, 
                           user_id: Optional[str] = None, username: str = "Unknown", 
                           source: str = "unknown") -> bool:
        """Update bot status with security validation"""
        try:
            status_map = {
                'playing': discord.ActivityType.playing,
                'watching': discord.ActivityType.watching,
                'listening': discord.ActivityType.listening,
                'streaming': discord.ActivityType.streaming,
                'competing': discord.ActivityType.competing
            }
            
            if status_type not in status_map:
                logger.warning(f"Invalid status type attempted: {status_type}")
                return False
            
            activity = discord.Activity(type=status_map[status_type], name=status_text)
            await self.bot.change_presence(status=discord.Status.online, activity=activity)
            
            if user_id:
                self.log_activity(user_id, username, "Status Update", 
                                f"{status_type}: {status_text}", source)
            
            logger.info(f"Status updated: {status_type} - {status_text}")
            return True
            
        except Exception as e:
            logger.error(f"Status update error: {e}")
            if user_id:
                self.log_security_event(
                    'status_update_error',
                    'MEDIUM',
                    f'Status update error: {str(e)}',
                    user_id=user_id
                )
            return False
    
    async def update_online_status(self, online_status: str, user_id: Optional[str] = None, 
                                  username: str = "Unknown", source: str = "unknown") -> bool:
        """Update bot online status"""
        try:
            status_map = {
                'online': discord.Status.online,
                'idle': discord.Status.idle,
                'dnd': discord.Status.dnd,
                'invisible': discord.Status.invisible,
            }
            
            if online_status not in status_map:
                logger.warning(f"Invalid online status attempted: {online_status}")
                return False
            
            # Preserve current activity
            current_activity = None
            if hasattr(self.bot, 'activity'):
                current_activity = self.bot.activity
            
            await self.bot.change_presence(status=status_map[online_status], activity=current_activity)
            
            if user_id:
                self.log_activity(user_id, username, "Online Status Update", online_status, source)
            
            logger.info(f"Online status updated: {online_status}")
            return True
            
        except Exception as e:
            logger.error(f"Online status update error: {e}")
            if user_id:
                self.log_security_event(
                    'online_status_update_error',
                    'MEDIUM',
                    f'Online status update error: {str(e)}',
                    user_id=user_id
                )
            return False
    
    async def clear_status(self, user_id: str = "", username: str = "Unknown", 
                          source: str = "unknown") -> bool:
        """Clear bot status"""
        try:
            await self.bot.change_presence(status=discord.Status.online, activity=None)
            
            if user_id:
                self.log_activity(user_id, username, "Status Cleared", None, source)
            
            logger.info("Status cleared")
            return True
            
        except Exception as e:
            logger.error(f"Clear status error: {e}")
            if user_id:
                self.log_security_event(
                    'clear_status_error',
                    'MEDIUM',
                    f'Clear status error: {str(e)}',
                    user_id=user_id
                )
            return False
    
    async def get_current_status(self) -> Dict[str, Any]:
        """Get current bot status"""
        try:
            status_info = {
                'online_status': str(self.bot.status) if hasattr(self.bot, 'status') else 'unknown',
                'activity': None
            }
            
            if hasattr(self.bot, 'activity') and self.bot.activity:
                status_info['activity'] = {
                    'type': str(self.bot.activity.type),
                    'name': self.bot.activity.name
                }
            
            return status_info
            
        except Exception as e:
            logger.error(f"Get status error: {e}")
            return {'error': str(e)}
    
    async def run(self):
        """Run the bot with IPC server"""
        # Setup signal handlers for graceful shutdown
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, shutting down...")
            asyncio.create_task(self.shutdown())
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start IPC server and bot concurrently
        try:
            await asyncio.gather(
                self.ipc_server.start_server(),
                self.bot.start(self.config['bot_token']),
                return_exceptions=True
            )
        except Exception as e:
            logger.error(f"Error running bot: {e}")
            await self.shutdown()
    
    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down bot...")
        
        try:
            if hasattr(self, 'bot') and not self.bot.is_closed():
                await self.bot.close()
            
            if hasattr(self, 'ipc_server') and self.ipc_server.server:
                self.ipc_server.server.close()
                await self.ipc_server.server.wait_closed()
                
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
        
        logger.info("Bot shutdown complete")

if __name__ == "__main__":
    # Ensure data directory exists with proper permissions
    os.makedirs('/app/data', exist_ok=True)
    os.chmod('/app/data', 0o700)
    
    # Run the secure bot
    bot = SecureDiscordBot()
    try:
        asyncio.run(bot.run())
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)