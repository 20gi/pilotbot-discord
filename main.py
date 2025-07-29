#!/usr/bin/env python3
"""
Main Application Runner for Secure Discord Bot System
Coordinates bot.py and web_backend.py with proper security and monitoring
"""

import asyncio
import logging
import os
import signal
import sys
import json
import subprocess
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/data/main.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class SecurityMonitor:
    """Security monitoring and alerting system"""
    
    def __init__(self):
        self.start_time = datetime.utcnow()
        self.alert_thresholds = {
            'failed_logins_per_hour': 10,
            'memory_usage_percent': 85,
            'disk_usage_percent': 90,
            'cpu_usage_percent': 95
        }
    
    def check_system_health(self) -> Dict[str, Any]:
        """Check system health metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            
            # Disk usage
            disk = psutil.disk_usage('/app/data')
            
            # Process counts
            bot_process = self._find_process('bot.py')
            web_process = self._find_process('web_backend.py')
            
            health_status = {
                'timestamp': datetime.utcnow().isoformat(),
                'uptime_seconds': (datetime.utcnow() - self.start_time).total_seconds(),
                'system': {
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_used_mb': memory.used // (1024 * 1024),
                    'disk_percent': disk.percent,
                    'disk_used_gb': disk.used // (1024 * 1024 * 1024)
                },
                'processes': {
                    'bot_running': bot_process is not None,
                    'web_running': web_process is not None,
                    'bot_pid': bot_process.pid if bot_process else None,
                    'web_pid': web_process.pid if web_process else None
                },
                'alerts': []
            }
            
            # Check thresholds and generate alerts
            if cpu_percent > self.alert_thresholds['cpu_usage_percent']:
                health_status['alerts'].append({
                    'type': 'HIGH_CPU_USAGE',
                    'severity': 'CRITICAL',
                    'message': f'CPU usage at {cpu_percent}%'
                })
            
            if memory.percent > self.alert_thresholds['memory_usage_percent']:
                health_status['alerts'].append({
                    'type': 'HIGH_MEMORY_USAGE',
                    'severity': 'CRITICAL',
                    'message': f'Memory usage at {memory.percent}%'
                })
            
            if disk.percent > self.alert_thresholds['disk_usage_percent']:
                health_status['alerts'].append({
                    'type': 'HIGH_DISK_USAGE',
                    'severity': 'CRITICAL',
                    'message': f'Disk usage at {disk.percent}%'
                })
            
            if not bot_process:
                health_status['alerts'].append({
                    'type': 'BOT_PROCESS_DOWN',
                    'severity': 'CRITICAL',
                    'message': 'Bot process is not running'
                })
            
            if not web_process:
                health_status['alerts'].append({
                    'type': 'WEB_PROCESS_DOWN',
                    'severity': 'CRITICAL',
                    'message': 'Web backend process is not running'
                })
            
            return health_status
            
        except Exception as e:
            logger.error(f"Health check error: {e}")
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e),
                'alerts': [{
                    'type': 'HEALTH_CHECK_ERROR',
                    'severity': 'HIGH',
                    'message': f'Health check failed: {str(e)}'
                }]
            }
    
    def _find_process(self, script_name: str) -> Optional[psutil.Process]:
        """Find process by script name"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                if proc.info['cmdline']:
                    cmdline = ' '.join(proc.info['cmdline'])
                    if script_name in cmdline and 'python' in cmdline:
                        return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return None

class ConfigValidator:
    """Configuration validation and security checks"""
    
    @staticmethod
    def validate_config_file() -> bool:
        """Validate configuration file exists and has required fields"""
        config_path = '/app/data/config.json'
        
        try:
            if not os.path.exists(config_path):
                logger.error("Configuration file not found")
                return False
            
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            required_fields = [
                'bot_token', 'discord_client_id', 'discord_client_secret',
                'jwt_secret', 'owner_id', 'allowed_users', 'base_url'
            ]
            
            missing_fields = []
            for field in required_fields:
                if field not in config or not config[field]:
                    missing_fields.append(field)
            
            if missing_fields:
                logger.error(f"Missing required configuration fields: {missing_fields}")
                return False
            
            # Validate field formats
            if not isinstance(config['owner_id'], (int, str)) or not str(config['owner_id']).isdigit():
                logger.error("Invalid owner_id format")
                return False
            
            if not isinstance(config['allowed_users'], list):
                logger.error("allowed_users must be a list")
                return False
            
            for user_id in config['allowed_users']:
                if not isinstance(user_id, (int, str)) or not str(user_id).isdigit():
                    logger.error(f"Invalid user_id format: {user_id}")
                    return False
            
            # Validate JWT secret strength
            if len(config['jwt_secret']) < 32:
                logger.error("JWT secret too short (minimum 32 characters)")
                return False
            
            # Validate Discord client credentials
            if len(config['discord_client_id']) < 18:
                logger.error("Invalid Discord client ID")
                return False
            
            if len(config['discord_client_secret']) < 32:
                logger.error("Invalid Discord client secret")
                return False
            
            # Validate bot token
            if not config['bot_token'].startswith(('Bot ', 'MTk', 'Mz', 'Nz', 'OD')):
                logger.warning("Bot token format may be invalid")
            
            logger.info("Configuration validation passed")
            return True
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in configuration file: {e}")
            return False
        except Exception as e:
            logger.error(f"Configuration validation error: {e}")
            return False
    
    @staticmethod
    def check_file_permissions():
        """Check and set secure file permissions"""
        try:
            # Ensure data directory exists with proper permissions
            os.makedirs('/app/data', exist_ok=True)
            os.chmod('/app/data', 0o700)
            
            # Set secure permissions for config file
            config_path = '/app/data/config.json'
            if os.path.exists(config_path):
                os.chmod(config_path, 0o600)
            
            # Set secure permissions for database files
            db_files = [
                '/app/data/bot_data.db',
                '/app/data/web_data.db'
            ]
            
            for db_file in db_files:
                if os.path.exists(db_file):
                    os.chmod(db_file, 0o600)
            
            # Set secure permissions for key files
            key_files = [
                '/app/data/ipc_secret.key'
            ]
            
            for key_file in key_files:
                if os.path.exists(key_file):
                    os.chmod(key_file, 0o600)
            
            logger.info("File permissions set securely")
            
        except Exception as e:
            logger.error(f"Failed to set file permissions: {e}")
            raise

class ProcessManager:
    """Manage bot and web backend processes"""
    
    def __init__(self):
        self.bot_process = None
        self.web_process = None
        self.shutdown_event = asyncio.Event()
        self.restart_attempts = {'bot': 0, 'web': 0}
        self.max_restart_attempts = 5
    
    async def start_bot(self):
        """Start bot process"""
        try:
            logger.info("Starting bot process...")
            self.bot_process = await asyncio.create_subprocess_exec(
                sys.executable, '/app/bot.py',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd='/app'
            )
            
            logger.info(f"Bot process started with PID: {self.bot_process.pid}")
            
            # Monitor bot process
            asyncio.create_task(self._monitor_process('bot', self.bot_process))
            
        except Exception as e:
            logger.error(f"Failed to start bot process: {e}")
            raise
    
    async def start_web_backend(self):
        """Start web backend process"""
        try:
            logger.info("Starting web backend process...")
            self.web_process = await asyncio.create_subprocess_exec(
                sys.executable, '/app/web_backend.py',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd='/app'
            )
            
            logger.info(f"Web backend process started with PID: {self.web_process.pid}")
            
            # Monitor web backend process
            asyncio.create_task(self._monitor_process('web', self.web_process))
            
        except Exception as e:
            logger.error(f"Failed to start web backend process: {e}")
            raise
    
    async def _monitor_process(self, process_name: str, process: asyncio.subprocess.Process):
        """Monitor process and handle restarts"""
        while not self.shutdown_event.is_set():
            try:
                # Check if process is still running
                if process.returncode is not None:
                    logger.error(f"{process_name} process exited with code: {process.returncode}")
                    
                    # Read any error output
                    try:
                        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
                        if stderr:
                            logger.error(f"{process_name} stderr: {stderr.decode()}")
                        if stdout:
                            logger.info(f"{process_name} stdout: {stdout.decode()}")
                    except asyncio.TimeoutError:
                        pass
                    
                    # Attempt restart if within limits
                    if self.restart_attempts[process_name] < self.max_restart_attempts:
                        self.restart_attempts[process_name] += 1
                        logger.info(f"Attempting to restart {process_name} (attempt {self.restart_attempts[process_name]})")
                        
                        await asyncio.sleep(5)  # Wait before restart
                        
                        if process_name == 'bot':
                            await self.start_bot()
                        elif process_name == 'web':
                            await self.start_web_backend()
                    else:
                        logger.critical(f"Max restart attempts reached for {process_name}")
                        self.shutdown_event.set()
                    
                    break
                
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Error monitoring {process_name} process: {e}")
                await asyncio.sleep(10)
    
    async def shutdown(self):
        """Graceful shutdown of all processes"""
        logger.info("Shutting down processes...")
        
        self.shutdown_event.set()
        
        # Terminate processes
        processes = []
        if self.bot_process and self.bot_process.returncode is None:
            processes.append(('bot', self.bot_process))
        
        if self.web_process and self.web_process.returncode is None:
            processes.append(('web', self.web_process))
        
        # Send SIGTERM to all processes
        for name, process in processes:
            try:
                process.terminate()
                logger.info(f"Sent SIGTERM to {name} process")
            except Exception as e:
                logger.error(f"Error terminating {name} process: {e}")
        
        # Wait for graceful shutdown
        for name, process in processes:
            try:
                await asyncio.wait_for(process.wait(), timeout=10)
                logger.info(f"{name} process shut down gracefully")
            except asyncio.TimeoutError:
                logger.warning(f"{name} process did not shut down gracefully, forcing...")
                try:
                    process.kill()
                    await process.wait()
                    logger.info(f"{name} process force killed")
                except Exception as e:
                    logger.error(f"Error force killing {name} process: {e}")
        
        logger.info("All processes shut down")

class HealthChecker:
    """Health monitoring and alerting"""
    
    def __init__(self, process_manager: ProcessManager):
        self.process_manager = process_manager
        self.security_monitor = SecurityMonitor()
        self.last_health_check = None
        self.consecutive_failures = 0
        
    async def start_health_monitoring(self):
        """Start health monitoring loop"""
        logger.info("Starting health monitoring...")
        
        while not self.process_manager.shutdown_event.is_set():
            try:
                health_status = self.security_monitor.check_system_health()
                self.last_health_check = health_status
                
                # Log critical alerts
                for alert in health_status.get('alerts', []):
                    if alert['severity'] == 'CRITICAL':
                        logger.critical(f"ALERT: {alert['type']} - {alert['message']}")
                    elif alert['severity'] == 'HIGH':
                        logger.error(f"ALERT: {alert['type']} - {alert['message']}")
                    else:
                        logger.warning(f"ALERT: {alert['type']} - {alert['message']}")
                
                # Reset failure counter on successful check
                self.consecutive_failures = 0
                
                # Wait before next check
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.consecutive_failures += 1
                logger.error(f"Health check failed ({self.consecutive_failures}): {e}")
                
                if self.consecutive_failures >= 5:
                    logger.critical("Multiple consecutive health check failures - system may be unstable")
                
                await asyncio.sleep(30)  # Shorter interval on failure
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status"""
        if self.last_health_check:
            return self.last_health_check
        else:
            return {
                'status': 'unknown',
                'message': 'Health monitoring not yet initialized'
            }

class SecureApplication:
    """Main secure application coordinator"""
    
    def __init__(self):
        self.process_manager = ProcessManager()
        self.health_checker = HealthChecker(self.process_manager)
        self.shutdown_requested = False
    
    async def startup_checks(self):
        """Perform startup security and configuration checks"""
        logger.info("Performing startup checks...")
        
        # Check file permissions
        ConfigValidator.check_file_permissions()
        
        # Validate configuration
        if not ConfigValidator.validate_config_file():
            logger.error("Configuration validation failed")
            sys.exit(1)
        
        # Check if running as root (security risk)
        if os.getuid() == 0:
            logger.warning("Running as root user - this is a security risk!")
        
        # Check available ports
        import socket
        
        ports_to_check = [8000, 9001]  # Web backend and IPC ports
        for port in ports_to_check:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                result = s.connect_ex(('127.0.0.1', port))
                if result == 0:
                    logger.error(f"Port {port} is already in use")
                    sys.exit(1)
        
        logger.info("Startup checks completed successfully")
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}")
            self.shutdown_requested = True
            asyncio.create_task(self.shutdown())
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        # Handle SIGUSR1 for health status
        def health_signal_handler(signum, frame):
            logger.info("Health status requested via signal")
            health_status = self.health_checker.get_health_status()
            logger.info(f"Health Status: {json.dumps(health_status, indent=2)}")
        
        signal.signal(signal.SIGUSR1, health_signal_handler)
        
        logger.info("Signal handlers configured")
    
    async def run(self):
        """Main application entry point"""
        try:
            logger.info("Starting Secure Discord Bot System")
            
            # Startup checks
            await self.startup_checks()
            
            # Setup signal handlers
            self.setup_signal_handlers()
            
            # Start processes
            await self.process_manager.start_bot()
            await asyncio.sleep(2)  # Give bot time to start IPC server
            await self.process_manager.start_web_backend()
            
            # Start health monitoring
            health_task = asyncio.create_task(self.health_checker.start_health_monitoring())
            
            logger.info("All systems started successfully")
            
            # Main loop - wait for shutdown
            while not self.shutdown_requested and not self.process_manager.shutdown_event.is_set():
                await asyncio.sleep(1)
            
            # Cancel health monitoring
            health_task.cancel()
            
            logger.info("Shutdown initiated")
            
        except Exception as e:
            logger.error(f"Fatal error in main application: {e}")
            raise
        finally:
            await self.shutdown()
    
    async def shutdown(self):
        """Graceful application shutdown"""
        if not hasattr(self, '_shutting_down'):
            self._shutting_down = True
            logger.info("Initiating graceful shutdown...")
            
            try:
                await self.process_manager.shutdown()
                logger.info("Secure Discord Bot System shut down complete")
            except Exception as e:
                logger.error(f"Error during shutdown: {e}")

def main():
    """Main entry point"""
    # Ensure we're running in the correct directory
    os.chdir('/app')
    
    # Create data directory if it doesn't exist
    os.makedirs('/app/data', exist_ok=True)
    
    # Initialize and run the application
    app = SecureApplication()
    
    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        logger.info("Application stopped by user")
    except Exception as e:
        logger.error(f"Fatal application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()