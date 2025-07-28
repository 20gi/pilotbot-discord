# bot.py (Formerly secure_bot_py.py)

import discord
from discord.ext import commands
import aiohttp
import os
import json
import secrets
import hashlib
import time
import logging
from datetime import datetime, timedelta
from functools import wraps
from threading import Thread
import asyncio
from urllib.parse import urlencode, quote_plus
import re

# Security imports
from flask import Flask, request, jsonify, session, redirect, url_for, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import requests
from werkzeug.middleware.proxy_fix import ProxyFix
import ipaddress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Bot setup with setup_hook for Cogs ---
class ControlBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = kwargs.get('config')

    async def setup_hook(self):
        # Load the slash command Cog
        await self.load_extension('bot_commands')
        logger.info("Successfully loaded 'bot_commands' Cog.")
        
        # Sync commands to the specific guild
        control_guild = discord.Object(id=int(self.config['control_server_id']))
        self.tree.copy_global_to(guild=control_guild)
        await self.tree.sync(guild=control_guild)
        logger.info(f"Synced slash commands to guild {self.config['control_server_id']}")
    
    # Define the bio update function here so both Cog and Web UI can access it
    async def update_bot_bio_from_cog(self, bio_text: str) -> bool:
        return await update_bot_bio(bio_text)


# Flask app setup with security hardening
app = Flask(__name__)

# Trust proxy headers if behind reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Security configuration
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY'),
    SESSION_COOKIE_SECURE=os.getenv('FLASK_ENV') == 'production',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    MAX_CONTENT_LENGTH=16 * 1024,  # 16KB max request size
)

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "10 per minute"],
    storage_uri="memory://",
)

# Security headers with Talisman
csp = {
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline'",
    'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com",
    'font-src': "'self' https://fonts.gstatic.com",
    'img-src': "'self' https://cdn.discordapp.com data:",
    'connect-src': "'self'",
    'frame-ancestors': "'none'",
}

Talisman(
    app,
    force_https=os.getenv('FLASK_ENV') == 'production',
    content_security_policy=csp,
    referrer_policy='strict-origin-when-cross-origin',
    feature_policy={
        'geolocation': "'none'",
        'microphone': "'none'",
        'camera': "'none'",
    }
)

# CORS with strict origin control
allowed_origins = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
CORS(app, 
     supports_credentials=True, 
     origins=allowed_origins,
     allow_headers=['Content-Type', 'Authorization'],
     methods=['GET', 'POST', 'OPTIONS'])

# Configuration validation
CONFIG_PATH = '/app/config.json'
REQUIRED_ENV_VARS = ['BOT_TOKEN', 'DISCORD_CLIENT_ID', 'DISCORD_CLIENT_SECRET', 'SECRET_KEY']
REQUIRED_CONFIG_KEYS = ['allowed_users', 'bot_owner_id', 'control_server_id', 'control_channel_id']

def validate_environment():
    """Validate all required environment variables are present"""
    missing_vars = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
    if missing_vars:
        logger.error(f"Missing required environment variables: {missing_vars}")
        raise ValueError(f"Missing environment variables: {missing_vars}")

def validate_config():
    """Validate configuration file"""
    try:
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        
        missing_keys = [key for key in REQUIRED_CONFIG_KEYS if key not in config]
        if missing_keys:
            raise ValueError(f"Missing required keys in config.json: {missing_keys}")
        
        # Validate user IDs are strings and look like Discord IDs
        for uid in config['allowed_users']:
            if not isinstance(uid, str) or not re.match(r'^\d{17,20}$', uid):
                raise ValueError(f"Invalid user ID format in allowed_users: {uid}")
        
        for key in ['bot_owner_id', 'control_server_id', 'control_channel_id']:
            if not isinstance(config[key], str) or not re.match(r'^\d{17,20}$', config[key]):
                raise ValueError(f"Invalid ID format for {key}: {config[key]}")

        return config
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        logger.error(f"Config validation failed: {e}")
        raise

# Load and validate configuration
try:
    validate_environment()
    config = validate_config()
    ALLOWED_USERS = set(config['allowed_users'])
    logger.info(f"Loaded {len(ALLOWED_USERS)} allowed users for Web UI.")
    logger.info(f"Slash commands configured for owner {config['bot_owner_id']} in channel {config['control_channel_id']}.")
except Exception as e:
    logger.error(f"Configuration error: {e}")
    exit(1)

# Bot instance creation
intents = discord.Intents.default()
bot = ControlBot(command_prefix='!', intents=intents, config=config)

# Environment variables with validation
BOT_TOKEN = os.getenv('BOT_TOKEN')
CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
REDIRECT_URI = os.getenv('REDIRECT_URI', 'http://localhost:5000/auth/callback')

# --- Shared Bot Functions ---
async def update_bot_bio(bio_text):
    """Update the bot's About Me section with error handling (SHARED)"""
    try:
        url = "https://discord.com/api/v10/users/@me"
        headers = {
            "Authorization": f"Bot {bot.http.token}",
            "Content-Type": "application/json",
            "User-Agent": "DiscordBot (https://your.project.url, 1.0)"
        }
        data = {"bio": bio_text}
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.patch(url, json=data, headers=headers) as response:
                if response.status == 200:
                    logger.info(f"Successfully updated bot bio")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to update bio: {response.status} - {error_text}")
                    return False
    except Exception as e:
        logger.error(f"Exception updating bio: {e}")
        return False

# --- Input validation functions (no changes needed) ---
def validate_bio_input(bio):
    if not isinstance(bio, str) or len(bio) > 190: return False
    dangerous_chars = ['<', '>', '"', "'", '&', '\x00']; return not any(char in bio for char in dangerous_chars)

def validate_status_input(status_type, status_text):
    valid_types = ['playing', 'watching', 'listening', 'streaming', 'competing']; valid_online = ['online', 'idle', 'dnd', 'invisible']
    if status_type and status_type not in valid_types: return False
    if status_text and (not isinstance(status_text, str) or len(status_text) > 128): return False
    return True

# --- Security decorators and logging (no changes needed) ---
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session['user_id'] not in ALLOWED_USERS:
            logger.warning(f"Unauthorized/Forbidden access attempt from {request.remote_addr} for user {session.get('user_id')}")
            return jsonify({'error': 'Access denied'}), 403
        if 'created_at' in session and datetime.fromisoformat(session['created_at']) < datetime.now() - timedelta(hours=24):
            session.clear(); return jsonify({'error': 'Session expired'}), 401
        return f(*args, **kwargs)
    return decorated_function

def log_action(action):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id', 'unknown'); ip = request.remote_addr
            logger.info(f"Web Action: {action} | User: {user_id} | IP: {ip}")
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Bot Events ---
@bot.event
async def on_ready():
    logger.info(f'{bot.user} has connected to Discord!')
    logger.info(f"Bot is ready for both Web UI and Slash Command control.")


# --- Flask Routes (no significant changes, just copy/paste the block from secure_bot_py.py) ---
@app.before_request
def security_checks():
    suspicious_headers = ['x-forwarded-host', 'x-original-url', 'x-rewrite-url']
    for header in suspicious_headers:
        if header in request.headers:
            logger.warning(f"Suspicious header {header} from {request.remote_addr}"); abort(400)
    if request.method == 'POST' and request.content_type and 'application/json' not in request.content_type: abort(400)

@app.route('/health')
@limiter.limit("5 per minute")
def health_check():
    return jsonify({'status': 'healthy', 'bot_connected': bot.is_ready(), 'timestamp': datetime.now().isoformat()})

@app.route('/api/auth/login')
@limiter.limit("5 per minute")
def login():
    state = secrets.token_urlsafe(32); session['oauth_state'] = state; session['state_created'] = datetime.now().isoformat()
    params = {'client_id': CLIENT_ID, 'redirect_uri': REDIRECT_URI, 'response_type': 'code', 'scope': 'identify', 'state': state}
    auth_url = f"https://discord.com/api/oauth2/authorize?{urlencode(params, quote_via=quote_plus)}"
    logger.info(f"OAuth login initiated from {request.remote_addr}"); return redirect(auth_url)

@app.route('/auth/callback')
@limiter.limit("10 per minute")
def auth_callback():
    code = request.args.get('code'); state = request.args.get('state')
    if request.args.get('error') or not code or not state:
        logger.warning(f"OAuth error/missing params from {request.remote_addr}"); return redirect(f"{allowed_origins[0]}/access-denied")
    stored_state = session.get('oauth_state'); state_created = session.get('state_created')
    if not stored_state or state != stored_state or (state_created and datetime.now() - datetime.fromisoformat(state_created) > timedelta(minutes=10)):
        logger.warning(f"Invalid/Expired OAuth state from {request.remote_addr}"); return redirect(f"{allowed_origins[0]}/access-denied")
    try:
        token_data = {'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET, 'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT_URI}
        token_response = requests.post('https://discord.com/api/oauth2/token', data=token_data, timeout=10)
        if token_response.status_code != 200: logger.error(f"Token exchange failed: {token_response.status_code}"); return redirect(f"{allowed_origins[0]}/access-denied")
        access_token = token_response.json().get('access_token')
        user_response = requests.get('https://discord.com/api/users/@me', headers={'Authorization': f'Bearer {access_token}'}, timeout=10)
        if user_response.status_code != 200: logger.error(f"User info request failed: {user_response.status_code}"); return redirect(f"{allowed_origins[0]}/access-denied")
        user_data = user_response.json(); user_id = user_data.get('id')
        if user_id not in ALLOWED_USERS:
            logger.warning(f"Access denied for user {user_id} from {request.remote_addr}"); return redirect(f"{allowed_origins[0]}/access-denied")
        session.permanent = True; session['user_id'] = user_id; session['username'] = user_data.get('username', 'Unknown'); session['avatar'] = user_data.get('avatar'); session['created_at'] = datetime.now().isoformat(); session['last_activity'] = datetime.now().isoformat()
        session.pop('oauth_state', None); session.pop('state_created', None)
        logger.info(f"User {user_id} successfully authenticated from {request.remote_addr}"); return redirect(f"{allowed_origins[0]}/dashboard")
    except requests.RequestException as e:
        logger.error(f"Network error during OAuth: {e}"); return redirect(f"{allowed_origins[0]}/access-denied")
    except Exception as e:
        logger.error(f"Unexpected error during OAuth: {e}"); return redirect(f"{allowed_origins[0]}/access-denied")

@app.route('/api/auth/user')
@limiter.limit("30 per minute")
@require_auth
def get_user():
    session['last_activity'] = datetime.now().isoformat()
    return jsonify({'authenticated': True, 'user_id': session['user_id'], 'username': session['username'], 'avatar': session.get('avatar')})

@app.route('/api/auth/logout', methods=['POST'])
@limiter.limit("10 per minute")
@require_auth
@log_action("logout")
def logout():
    session.clear(); return jsonify({'success': True})

@app.route('/api/bot/status', methods=['POST'])
@limiter.limit("20 per minute")
@require_auth
@log_action("update_status")
def set_bot_status():
    data = request.get_json()
    if not data or not validate_status_input(data.get('type'), data.get('text')) or data.get('online_status') not in ['online', 'idle', 'dnd', 'invisible']:
        return jsonify({'error': 'Invalid input'}), 400
    status_type, status_text, online_status = data.get('type'), data.get('text'), data.get('online_status')
    def run_update():
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        try:
            status_map = {'playing': discord.ActivityType.playing, 'watching': discord.ActivityType.watching, 'listening': discord.ActivityType.listening, 'streaming': discord.ActivityType.streaming, 'competing': discord.ActivityType.competing}
            online_map = {'online': discord.Status.online, 'idle': discord.Status.idle, 'dnd': discord.Status.dnd, 'invisible': discord.Status.invisible}
            activity = discord.Activity(type=status_map[status_type], name=status_text) if status_type and status_text else None
            future = asyncio.run_coroutine_threadsafe(bot.change_presence(status=online_map[online_status], activity=activity), bot.loop)
            future.result(timeout=10)
        except Exception as e: logger.error(f"Error in status thread: {e}")
        finally: loop.close()
    Thread(target=run_update, daemon=True).start(); return jsonify({'success': True})

@app.route('/api/bot/bio', methods=['POST'])
@limiter.limit("10 per minute")
@require_auth
@log_action("update_bio")
def update_bio():
    data = request.get_json()
    if not data or not validate_bio_input(data.get('bio', '')): return jsonify({'error': 'Invalid bio content'}), 400
    bio_text = data.get('bio', '').strip()
    def run_update():
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        try:
            future = asyncio.run_coroutine_threadsafe(update_bot_bio(bio_text), bot.loop)
            future.result(timeout=10)
        except Exception as e: logger.error(f"Error in bio thread: {e}")
        finally: loop.close()
    Thread(target=run_update, daemon=True).start(); return jsonify({'success': True})

@app.route('/api/bot/clear-status', methods=['POST'])
@limiter.limit("10 per minute")
@require_auth
@log_action("clear_status")
def clear_status():
    def run_update():
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        try:
            future = asyncio.run_coroutine_threadsafe(bot.change_presence(status=discord.Status.online, activity=None), bot.loop)
            future.result(timeout=10)
        except Exception as e: logger.error(f"Error in clear status thread: {e}")
        finally: loop.close()
    Thread(target=run_update, daemon=True).start(); return jsonify({'success': True})

# --- Error handlers (no changes needed) ---
@app.errorhandler(400)
def bad_request(e): return jsonify({'error': 'Bad request'}), 400
@app.errorhandler(401)
def unauthorized(e): return jsonify({'error': 'Unauthorized'}), 401
@app.errorhandler(403)
def forbidden(e): return jsonify({'error': 'Forbidden'}), 403
@app.errorhandler(404)
def not_found(e): return jsonify({'error': 'Not found'}), 404
@app.errorhandler(429)
def ratelimit_handler(e): return jsonify({'error': 'Rate limit exceeded'}), 429
@app.errorhandler(500)
def internal_error(e): logger.error(f"Internal server error: {e}"); return jsonify({'error': 'Internal server error'}), 500

# --- Main Execution ---
def run_flask():
    # This should not be used in production directly. Gunicorn will run the app.
    # It's here for local testing if needed.
    logger.info("Flask development server is for testing only. Use Gunicorn in production.")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)

def run_bot():
    try:
        bot.run(BOT_TOKEN, log_handler=None)  # We handle logging ourselves
    except Exception as e:
        logger.critical(f"Bot startup failed: {e}")
        raise

if __name__ == '__main__':
    logger.info("Starting Discord Bot Control Panel")
    os.makedirs('/app/logs', exist_ok=True)
    flask_thread = Thread(target=run_flask, daemon=True)
    flask_thread.start()
    run_bot()

# Note for Gunicorn: Gunicorn will import the `app` object from this file.
# The `if __name__ == '__main__':` block will still run the bot when the module is executed.
# However, the Gunicorn command in your Dockerfile (`bot:app`) will make Flask the primary process.
# To run both, we need to adjust the startup logic slightly. The current approach with a
# separate thread for Flask and the bot in the main thread is problematic with Gunicorn.
# A better production pattern is to run the bot in the main `if __name__ == '__main__'` block
# and let Gunicorn handle the Flask app. The provided Docker CMD already targets `gunicorn ... bot:app`.
# Let's adjust the `if __name__` block to only run the bot, assuming Gunicorn handles Flask.

# Let's re-think the entrypoint for Gunicorn. Gunicorn needs to load the `app` object.
# The bot needs to run in its own loop. The threaded model is actually the most straightforward way
# to get them running in the same container process. We'll stick with the thread-based startup.
# The `CMD` in the Dockerfile `["gunicorn", "--config", "gunicorn.conf.py", "bot:app"]` will start gunicorn,
# which loads `bot.py` and finds the `app` object. When a python module is imported, its top-level code runs.
# This means the bot will start when Gunicorn imports the file. To prevent this, we will move the bot
# startup into a Gunicorn hook.

# No, the gunicorn.conf.py `preload_app = True` will cause issues.
# The simplest approach that works with the existing Docker/Gunicorn setup is to run the bot
# in a background thread when the app is initialized.

def start_bot_in_background():
    """Starts the bot in a background thread."""
    loop = asyncio.get_event_loop()
    loop.create_task(bot.start(BOT_TOKEN, log_handler=None))
    Thread(target=loop.run_forever, daemon=True).start()
    logger.info("Discord bot started in background thread.")

# The Flask app will be found by Gunicorn. When it's loaded, start the bot.
# This part of the code will run when Gunicorn imports the module.
start_bot_in_background()