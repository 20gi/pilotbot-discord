import discord
import logging
from discord import app_commands
from discord.ext import commands
import aiohttp
import os
import json
import re
from datetime import datetime, timezone
import asyncio
from pathlib import Path
from typing import Dict, List
import yaml
from pilot_chat import setup_pilot_chat
import ssl
from web_api import start_web_server, DEFAULT_WEB_PORT

logger = logging.getLogger(__name__)

# --- Configuration loading -------------------------------------------------
DEFAULT_CONFIG_FILE = os.getenv('BOT_CONFIG_FILE')
DEFAULT_DATA_DIR = Path(os.getenv('DATA_DIR', 'data'))


def _load_yaml_options(path: Path) -> dict:
    try:
        if not path or not path.exists():
            return {}
        with path.open('r', encoding='utf-8') as handle:
            data = yaml.safe_load(handle) or {}
            if isinstance(data, dict):
                if 'options' in data and isinstance(data['options'], dict):
                    return data['options']
                return data
            return {}
    except Exception as exc:
        logger.warning("Failed to load configuration file %s: %s", path, exc)
        return {}


def _parse_bool(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on', 'y'}


def _parse_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _read_secret_file(path: str | None) -> str | None:
    if not path:
        return None
    try:
        data = Path(path).read_text(encoding='utf-8').strip()
        return data or None
    except Exception as exc:
        logger.warning("Failed to read secret file %s: %s", path, exc)
        return None


def load_settings() -> dict:
    config: dict = {}

    if DEFAULT_CONFIG_FILE:
        config.update(_load_yaml_options(Path(DEFAULT_CONFIG_FILE)))
    else:
        fallback = Path('config.yaml')
        if fallback.exists():
            config.update(_load_yaml_options(fallback))

    # Environment variable overrides
    env_overrides = {
        'bot_token': os.getenv('BOT_TOKEN'),
        'chutes_api_key': os.getenv('CHUTES_API_KEY'),
        'chutes_model': os.getenv('CHUTES_MODEL'),
        'pilot_history_limit': _parse_int(os.getenv('PILOT_HISTORY_LIMIT')),
        'pilot_response_channel_id': os.getenv('PILOT_RESPONSE_CHANNEL_ID'),
        'pilot_enabled': _parse_bool(os.getenv('PILOT_ENABLED')),
        'pilot_style_mode': os.getenv('PILOT_STYLE_MODE'),
        'web_port': _parse_int(os.getenv('WEB_PORT')),
        'web_ssl_cert_path': os.getenv('WEB_SSL_CERT_PATH'),
        'web_ssl_key_path': os.getenv('WEB_SSL_KEY_PATH'),
        'web_auth_token': os.getenv('WEB_AUTH_TOKEN'),
        'web_oauth_client_id': os.getenv('WEB_OAUTH_CLIENT_ID'),
        'web_oauth_client_secret': os.getenv('WEB_OAUTH_CLIENT_SECRET'),
        'web_oauth_redirect_uri': os.getenv('WEB_OAUTH_REDIRECT_URI'),
        'web_session_secret': os.getenv('WEB_SESSION_SECRET'),
        'web_allowed_users': os.getenv('WEB_ALLOWED_USERS'),
        'control_server_id': _parse_int(os.getenv('CONTROL_SERVER_ID')),
        'control_channel_id': _parse_int(os.getenv('CONTROL_CHANNEL_ID')),
        'monitoring_channel_id': _parse_int(os.getenv('MONITORING_CHANNEL_ID')),
        'tracking_data_path': os.getenv('TRACKING_DATA_PATH'),
    }

    for key, value in env_overrides.items():
        if value is not None:
            config[key] = value

    secret_files = {
        'bot_token': os.getenv('BOT_TOKEN_FILE'),
        'chutes_api_key': os.getenv('CHUTES_API_KEY_FILE'),
        'web_auth_token': os.getenv('WEB_AUTH_TOKEN_FILE'),
        'web_oauth_client_secret': os.getenv('WEB_OAUTH_CLIENT_SECRET_FILE'),
        'web_session_secret': os.getenv('WEB_SESSION_SECRET_FILE'),
    }

    for key, file_path in secret_files.items():
        secret = _read_secret_file(file_path)
        if secret is not None:
            config[key] = secret

    # Ensure numeric / boolean coercion after potential overrides
    if 'pilot_enabled' in config:
        config['pilot_enabled'] = bool(_parse_bool(config['pilot_enabled']))
    if 'pilot_history_limit' in config:
        parsed = _parse_int(config['pilot_history_limit'])
        if parsed is not None:
            config['pilot_history_limit'] = parsed
    if 'web_port' in config:
        parsed = _parse_int(config['web_port'])
        if parsed is not None:
            config['web_port'] = parsed
    for key in ('control_server_id', 'control_channel_id', 'monitoring_channel_id'):
        if key in config:
            parsed = _parse_int(config[key])
            if parsed is not None:
                config[key] = parsed

    return config


OPTIONS = load_settings()
OPTIONS.setdefault('pilot_history_limit', 300)
OPTIONS.setdefault('pilot_enabled', False)
OPTIONS.setdefault('pilot_style_mode', 'default')
OPTIONS.setdefault('chutes_model', 'deepseek-ai/DeepSeek-V3-0324')

DATA_DIR = DEFAULT_DATA_DIR
DATA_DIR.mkdir(parents=True, exist_ok=True)

TRACKING_DATA_PATH = Path(
    OPTIONS.get('tracking_data_path')
    or os.getenv('TRACKING_DATA_PATH', DATA_DIR / 'lillian_tracking.json')
)
TRACKING_DATA_PATH = Path(TRACKING_DATA_PATH)
TRACKING_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)

# --- Discord bot setup -----------------------------------------------------
intents = discord.Intents.default()
intents.members = True  # Required for member join/leave events
intents.presences = True  # Required for tracking owner's presence
intents.message_content = True  # Required for reading messages to build history
bot = commands.Bot(command_prefix='!', intents=intents)

# --- Pilot Chat Cog holder ---
PILOT_COG = None


def _int_with_default(key: str, default: int) -> int:
    value = _parse_int(OPTIONS.get(key)) if key in OPTIONS else None
    return value if value is not None else default


# --- Control Server and Channel IDs ---
CONTROL_SERVER_ID = _int_with_default('control_server_id', 1258526802599481375)
CONTROL_CHANNEL_ID = _int_with_default('control_channel_id', 1311918837528002600)
MONITORING_CHANNEL_ID = _int_with_default('monitoring_channel_id', 1399788089307566111)
CONTROL_GUILD = discord.Object(id=CONTROL_SERVER_ID)
# ------------------------------------

# Command Tree for slash commands
tree = bot.tree

log_level_name = os.getenv('LOG_LEVEL', 'INFO').upper()
log_level = getattr(logging, log_level_name, logging.INFO)

# Configure basic logging if not already configured
if not logging.getLogger().hasHandlers():
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
else:
    logging.getLogger().setLevel(log_level)

# --- Owner Status Tracking Variables ---
owner_status_sync_enabled = False
bot_original_activity = None
bot_was_manually_set_offline = False

# --- Custom Exceptions for Error Handling ---
class NotOwnerError(app_commands.CheckFailure):
    """Exception raised when a command is used by a non-owner."""
    pass

class WrongChannelError(app_commands.CheckFailure):
    """Exception raised when a command is used in the wrong channel."""
    pass
# -----------------------------------------

# --- Tracking Data Management ---
def load_tracking_data():
    """Load tracking data from JSON file"""
    try:
        with TRACKING_DATA_PATH.open('r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        # Initialize with default structure
        default_data = {
            "tracked_user_id": None,
            "current_session": None,
            "leaderboard": []
        }
        save_tracking_data(default_data)
        return default_data
    except json.JSONDecodeError:
        logger.error("Could not decode JSON from %s", TRACKING_DATA_PATH)
        return {"tracked_user_id": None, "current_session": None, "leaderboard": []}

def save_tracking_data(data):
    """Save tracking data to JSON file"""
    try:
        with TRACKING_DATA_PATH.open('w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error("Error saving tracking data: %s", e)


ENTRY_REGEX = re.compile(
    r"Duration:</span></strong><span>\s*([^<]+?)\s*</span>"  # duration capture
    r".*?Joined:</span>.*?hiddenVisually[^>]*>([^<]+)<"      # joined timestamp
    r"(?:(?:.*?Left:</span>).*?hiddenVisually[^>]*>([^<]+)<)?",
    re.DOTALL,
)


TIMESTAMP_FORMATS = [
    "%A, %B %d, %Y %I:%M %p",
    "%B %d, %Y %I:%M %p",
    "%m/%d/%Y %I:%M %p",
    "%m/%d/%Y",
]


def _parse_migration_timestamp(value: str) -> str:
    cleaned = value.replace('\xa0', ' ').strip()
    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(cleaned, fmt)
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    raise ValueError(f"Unrecognised timestamp format: {value!r}")


def parse_lillian_migration(html: str, user_id: int) -> tuple[List[Dict[str, str]], Dict[str, str] | None]:
    normalized = html.replace('\r', '')
    matches = ENTRY_REGEX.findall(normalized)
    if not matches:
        raise ValueError("No leaderboard entries detected in provided file.")

    leaderboard: List[Dict[str, str]] = []
    current_session = None

    for duration, joined_raw, left_raw in matches:
        joined_iso = _parse_migration_timestamp(joined_raw)
        if left_raw:
            left_iso = _parse_migration_timestamp(left_raw)
            leaderboard.append({
                "duration": duration.strip(),
                "join_time": joined_iso,
                "leave_time": left_iso,
                "user_id": user_id,
            })
        elif current_session is None:
            current_session = {
                "join_time": joined_iso,
                "user_id": user_id,
            }

    return leaderboard, current_session

def format_duration(start_time, end_time):
    """Calculate and format duration between two timestamps"""
    start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
    end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
    duration = end - start
    
    days = duration.days
    hours, remainder = divmod(duration.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    
    if days > 0:
        return f"{days} days, {hours} hours, {minutes} minutes"
    elif hours > 0:
        return f"{hours} hours, {minutes} minutes"
    else:
        return f"{minutes} minutes"

async def send_monitoring_message(message=None, embed=None):
    """Send a message to the monitoring channel"""
    try:
        channel = bot.get_channel(MONITORING_CHANNEL_ID)
        if channel:
            if embed:
                await channel.send(embed=embed)
            elif message:
                await channel.send(message)
        else:
            logger.warning("Monitoring channel %s not found", MONITORING_CHANNEL_ID)
    except Exception as e:
        logger.error("Error sending monitoring message: %s", e)

# --- Owner Presence Tracking ---
@bot.event
async def on_presence_update(before, after):
    """Handle presence updates to sync bot status with owner status"""
    global owner_status_sync_enabled, bot_original_activity, bot_was_manually_set_offline
    
    # Only track the owner's presence
    if after.id != bot.owner_id or not owner_status_sync_enabled:
        return
    
    # Check if owner went offline
    if before.status != discord.Status.offline and after.status == discord.Status.offline:
        logger.info("Owner went offline, setting bot to invisible")
        # Store current activity before going offline
        if bot.user:
            guild = bot.get_guild(CONTROL_SERVER_ID)
            if guild and guild.me:
                bot_original_activity = guild.me.activity
        
        await bot.change_presence(status=discord.Status.invisible, activity=None)
        bot_was_manually_set_offline = False
        
    # Check if owner came back online
    elif before.status == discord.Status.offline and after.status != discord.Status.offline:
        logger.info("Owner came online, setting bot back to online")
        # Restore original activity or set default
        activity = bot_original_activity or discord.Activity(type=discord.ActivityType.watching, name="i hate dusekkar")
        await bot.change_presence(status=discord.Status.online, activity=activity)
        bot_was_manually_set_offline = False

# --- Member Events ---
@bot.event
async def on_member_join(member):
    """Handle member join events"""
    tracking_data = load_tracking_data()
    
    if tracking_data["tracked_user_id"] and member.id == tracking_data["tracked_user_id"]:
        join_time = datetime.now(timezone.utc).isoformat()
        tracking_data["current_session"] = {
            "join_time": join_time,
            "user_id": member.id
        }
        save_tracking_data(tracking_data)
        
        embed = discord.Embed(
            title="🟢 Lillian's train has arrived!",
            description="Rejoyce! Rejoyce!",
            color=0x00ff00,
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="User", value=f"{member.mention}", inline=True)
        embed.add_field(name="Join Time", value=f"<t:{int(datetime.now(timezone.utc).timestamp())}:F>", inline=True)
        
        await send_monitoring_message(embed=embed)

@bot.event
async def on_member_remove(member):
    """Handle member leave events"""
    tracking_data = load_tracking_data()
    
    if (tracking_data["tracked_user_id"] and 
        member.id == tracking_data["tracked_user_id"] and 
        tracking_data["current_session"]):
        
        leave_time = datetime.now(timezone.utc).isoformat()
        session = tracking_data["current_session"]
        
        # Calculate duration
        duration_str = format_duration(session["join_time"], leave_time)
        
        # Add to leaderboard
        leaderboard_entry = {
            "join_time": session["join_time"],
            "leave_time": leave_time,
            "duration": duration_str,
            "user_id": member.id
        }
        
        tracking_data["leaderboard"].append(leaderboard_entry)
        tracking_data["current_session"] = None
        
        # Sort leaderboard by duration (longest first)
        tracking_data["leaderboard"].sort(key=lambda x: datetime.fromisoformat(x["leave_time"].replace('Z', '+00:00')) - datetime.fromisoformat(x["join_time"].replace('Z', '+00:00')), reverse=True)
        
        save_tracking_data(tracking_data)
        
        # Send leave notification
        embed = discord.Embed(
            title="🔴 Lillian's train has departed",
            description="The server will now be dead for about a week.",
            color=0xff0000,
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="User", value=f"{member.mention}", inline=True)
        embed.add_field(name="Duration in Server", value=duration_str, inline=True)
        embed.add_field(name="Leave Time", value=f"<t:{int(datetime.now(timezone.utc).timestamp())}:F>", inline=True)
        
        await send_monitoring_message(embed=embed)
        
        # Send updated leaderboard
        leaderboard_embed = discord.Embed(
            title="🏆 Updated Lillian's Server Time Leaderboard",
            description="Longest to shortest server sessions",
            color=0xffd700,
            timestamp=datetime.now(timezone.utc)
        )
        
        # Show top 10 entries
        for i, entry in enumerate(tracking_data["leaderboard"][:10], 1):
            join_time = datetime.fromisoformat(entry["join_time"].replace('Z', '+00:00'))
            leave_time = datetime.fromisoformat(entry["leave_time"].replace('Z', '+00:00'))
            
            medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"{i}."
            
            # Highlight the most recent session (first in sorted list)
            is_latest = (entry["join_time"] == leaderboard_entry["join_time"])
            name_prefix = "**✨ " if is_latest else ""
            name_suffix = " ✨**" if is_latest else ""
            
            leaderboard_embed.add_field(
                name=f"{name_prefix}{medal} Session {i}{name_suffix}",
                value=f"**Duration:** {entry['duration']}\n"
                      f"**Joined:** <t:{int(join_time.timestamp())}:d>\n"
                      f"**Left:** <t:{int(leave_time.timestamp())}:d>",
                inline=True
            )
        
        total_sessions = len(tracking_data["leaderboard"])
        leaderboard_embed.set_footer(text=f"Total sessions recorded: {total_sessions} | ✨ = Latest session")
        
        await send_monitoring_message(embed=leaderboard_embed)

async def update_bot_bio(bio_text):
    """Update the bot's About Me section"""
    url = "https://discord.com/api/v10/users/@me"
    headers = {
        "Authorization": f"Bot {bot.http.token}",
        "Content-Type": "application/json"
    }
    data = {
        "bio": bio_text
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.patch(url, json=data, headers=headers) as response:
            if response.status == 200:
                logger.info("Updated bot bio")
            else:
                logger.error("Failed to update bio: %s", response.status)
                error_text = await response.text()
                logger.error("Discord API response: %s", error_text)

# Custom check that raises specific errors for different failures
def is_owner_and_in_control_channel():
    async def predicate(interaction: discord.Interaction) -> bool:
        if bot.owner_id is None:
            # Bot is not ready yet, deny access
            return False
        
        # First, check if the user is the owner
        if interaction.user.id != bot.owner_id:
            raise NotOwnerError()

        # If they are the owner, then check if they are in the right channel
        if interaction.channel_id != CONTROL_CHANNEL_ID:
            raise WrongChannelError()
            
        # If both checks pass, allow the command
        return True
    return app_commands.check(predicate)

@bot.event
async def on_ready():
    logger.info("%s has connected to Discord", bot.user)

    app_info = await bot.application_info()
    bot.owner_id = app_info.owner.id
    logger.info("Owner ID set to: %s", bot.owner_id)

    options = OPTIONS.copy()

    # Parse channel id safely from string to avoid precision loss
    raw_channel = options.get('pilot_response_channel_id')
    parsed_channel = None
    if raw_channel not in (None, "", 0, "0"):
        try:
            parsed_channel = int(str(raw_channel))
        except Exception as e:
            logger.warning("Invalid pilot_response_channel_id '%s': %s", raw_channel, e)

    pilot_config = {
        'pilot_enabled': bool(options.get('pilot_enabled', False)),
        'pilot_history_limit': int(options.get('pilot_history_limit', 300)),
        'chutes_model': options.get('chutes_model', 'deepseek-ai/DeepSeek-V3-0324'),
        'chutes_api_key': options.get('chutes_api_key'),
        'pilot_response_channel_id': parsed_channel,
        'pilot_style_mode': options.get('pilot_style_mode', 'default'),
    }

    # Print Chutes API key status (masked by default)
    def _mask_key(k: str) -> str:
        if not k:
            return ''
        if len(k) <= 8:
            return '*' * (len(k) - 2) + k[-2:]
        return f"{k[:4]}{'*' * (len(k) - 8)}{k[-4:]}"

    full_key = bool(os.getenv('CHUTES_PRINT_FULL_KEY'))
    key_to_show = pilot_config.get('chutes_api_key')
    if key_to_show:
        if full_key:
            logger.info("Chutes API key: %s", key_to_show)
        else:
            logger.info(
                "Chutes API key (masked): %s — set CHUTES_PRINT_FULL_KEY=1 to show full key",
                _mask_key(key_to_show),
            )
    else:
        logger.info("Chutes API key not set")

    global PILOT_COG
    if PILOT_COG is None:
        PILOT_COG = await setup_pilot_chat(
            bot=bot,
            control_guild=CONTROL_GUILD,
            control_channel_id=CONTROL_CHANNEL_ID,
            config=pilot_config,
        )

    # Pass owner username into Cog for prompt substitution
    try:
        PILOT_COG.set_owner_username(app_info.owner.name)
    except Exception:
        PILOT_COG.set_owner_username(str(app_info.owner.id))

    await tree.sync(guild=CONTROL_GUILD)
    logger.info("Synced slash commands for guild: %s", CONTROL_SERVER_ID)

    await bot.change_presence(
        status=discord.Status.online,
        activity=discord.Activity(type=discord.ActivityType.watching, name="i hate dusekkar")
    )
    logger.info("Status set to: Watching i hate dusekkar")

    # --- Start Web API server (HTTPS if certs provided) ---
    web_port = options.get('web_port', DEFAULT_WEB_PORT)
    try:
        web_port = int(web_port)
    except Exception:
        web_port = DEFAULT_WEB_PORT

    cert_path = options.get('web_ssl_cert_path')
    key_path = options.get('web_ssl_key_path')
    auth_token = options.get('web_auth_token') or ""

    # Discord OAuth config for Web UI
    oauth_client_id = options.get('web_oauth_client_id')
    oauth_client_secret = options.get('web_oauth_client_secret')
    oauth_redirect_uri = options.get('web_oauth_redirect_uri')
    session_secret = options.get('web_session_secret')

    # Allowed users and permissions
    allowed_users = {}
    raw_allowed = options.get('web_allowed_users')
    # Support multiple formats: dict mapping, list of {id, perms}, or CSV string "id:perm|perm,id2:view"
    try:
        if isinstance(raw_allowed, dict):
            for k, v in raw_allowed.items():
                if isinstance(v, (list, tuple)):
                    allowed_users[str(k)] = list(v)
        elif isinstance(raw_allowed, list):
            for item in raw_allowed:
                if isinstance(item, dict) and 'id' in item and 'perms' in item:
                    perms = item['perms'] if isinstance(item['perms'], list) else str(item['perms']).split('|')
                    allowed_users[str(item['id'])] = [p.strip() for p in perms if p.strip()]
        elif isinstance(raw_allowed, str):
            # id:perm|perm,id2:view
            for part in raw_allowed.split(','):
                part = part.strip()
                if not part:
                    continue
                if ':' not in part:
                    continue
                uid, perms = part.split(':', 1)
                allowed_users[str(uid.strip())] = [p.strip() for p in perms.split('|') if p.strip()]
    except Exception as e:
        logger.warning("Failed to parse web_allowed_users: %s", e)

    ssl_context = None
    if cert_path and key_path and os.path.exists(str(cert_path)) and os.path.exists(str(key_path)):
        try:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
            logger.info("Configured HTTPS with cert=%s key=%s", cert_path, key_path)
        except Exception as e:
            logger.warning("Failed to configure SSL, falling back to HTTP: %s", e)
            ssl_context = None
    else:
        logger.info("SSL cert/key not provided or not found; starting Web API over HTTP")

    if not getattr(bot, '_web_server_started', False):
        logging.info(
            "Launching web API host=0.0.0.0 port=%s ssl=%s oauth_client_id=%s allowed_users=%d",
            web_port,
            bool(ssl_context),
            oauth_client_id,
            len(allowed_users),
        )
        try:
            await start_web_server(
                bot,
                host='0.0.0.0',
                port=web_port,
                ssl_context=ssl_context,
                auth_token=auth_token,
                oauth_client_id=oauth_client_id,
                oauth_client_secret=oauth_client_secret,
                oauth_redirect_uri=oauth_redirect_uri,
                session_secret=session_secret,
                allowed_users=allowed_users,
            )
        except Exception as e:
            logging.exception("Web API failed to start on port %s: %s", web_port, e)
        else:
            setattr(bot, '_web_server_started', True)

# --- end of Pilot chatbot logic moved to bot/pilot_chat.py ---

# --- Original Bot Commands ---
@tree.command(name='updatebio', description='update the bot bio', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def update_bio_command(interaction: discord.Interaction, new_bio: str):
    await interaction.response.defer() 
    await update_bot_bio(new_bio)
    await interaction.followup.send(f"bio updated to: {new_bio}")

@tree.command(name='setstatus', description='change the bot\'s activity status', guild=CONTROL_GUILD)
@app_commands.choices(status_type=[
    app_commands.Choice(name='Playing', value='playing'),
    app_commands.Choice(name='Watching', value='watching'),
    app_commands.Choice(name='Listening to', value='listening'),
    app_commands.Choice(name='Streaming', value='streaming'),
    app_commands.Choice(name='Competing in', value='competing'),
])
@is_owner_and_in_control_channel()
async def set_status_command(interaction: discord.Interaction, status_type: app_commands.Choice[str], status_text: str):
    global bot_original_activity, bot_was_manually_set_offline
    
    status_map = {
        'playing': discord.ActivityType.playing, 'watching': discord.ActivityType.watching,
        'listening': discord.ActivityType.listening, 'streaming': discord.ActivityType.streaming,
        'competing': discord.ActivityType.competing
    }
    activity = discord.Activity(type=status_map[status_type.value], name=status_text)
    await bot.change_presence(status=discord.Status.online, activity=activity)
    
    # Update stored activity for owner sync
    bot_original_activity = activity
    bot_was_manually_set_offline = False
    
    await interaction.response.send_message(f"anything for you 😘😘: {status_type.name} {status_text}")

@tree.command(name='setonline', description='change the bot\'s online status', guild=CONTROL_GUILD)
@app_commands.choices(online_status=[
    app_commands.Choice(name='Online', value='online'), app_commands.Choice(name='Idle', value='idle'),
    app_commands.Choice(name='Do Not Disturb', value='dnd'), app_commands.Choice(name='Invisible', value='invisible'),
])
@is_owner_and_in_control_channel()
async def set_online_status(interaction: discord.Interaction, online_status: app_commands.Choice[str]):
    global bot_was_manually_set_offline
    
    status_map = {
        'online': discord.Status.online, 'idle': discord.Status.idle,
        'dnd': discord.Status.dnd, 'invisible': discord.Status.invisible,
    }
    current_activity = interaction.guild.me.activity
    await bot.change_presence(status=status_map[online_status.value], activity=current_activity)
    
    # Track if manually set to invisible
    if online_status.value == 'invisible':
        bot_was_manually_set_offline = True
    else:
        bot_was_manually_set_offline = False
    
    await interaction.response.send_message(f"status changed to: {online_status.name}")

@tree.command(name='clearstatus', description='clear the bot\'s activity status', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def clear_status_command(interaction: discord.Interaction):
    global bot_original_activity, bot_was_manually_set_offline
    
    await bot.change_presence(status=discord.Status.online, activity=None)
    bot_original_activity = None
    bot_was_manually_set_offline = False
    
    await interaction.response.send_message("status cleared")

# --- New Owner Status Sync Commands ---
@tree.command(name='syncme', description='pilot syncs online activity with me', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def enable_owner_sync(interaction: discord.Interaction):
    global owner_status_sync_enabled
    
    owner_status_sync_enabled = True
    await interaction.response.send_message("hi ofc ill sync with you!! 😍😍😍😍😍😘😘😘😘")

@tree.command(name='nosync', description='disables syncing', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def disable_owner_sync(interaction: discord.Interaction):
    global owner_status_sync_enabled
    
    owner_status_sync_enabled = False
    await interaction.response.send_message("okay ill stay online")

@tree.command(name='syncstatus', description='check if owner sync is enabled', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def sync_settings(interaction: discord.Interaction):
    global owner_status_sync_enabled, bot_original_activity
    
    sync_status = "enabled" if owner_status_sync_enabled else "disabled"
    activity_text = "none" if not bot_original_activity else f"{bot_original_activity.type.name.lower()}: {bot_original_activity.name}"
    
    # Check owner's current status
    guild = bot.get_guild(CONTROL_SERVER_ID)
    owner_status = "unknown"
    if guild:
        owner = guild.get_member(bot.owner_id)
        if owner:
            owner_status = owner.status.name.lower()
    
    await interaction.response.send_message(f"sync: {sync_status}\nstored activity: {activity_text}\nyour status: {owner_status}")

# --- New Tracking Commands ---
@tree.command(name='settrackuser', description='set the user ID to track (will be referred to as Lillian)', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def set_track_user(interaction: discord.Interaction, user_id: str):
    try:
        user_id_int = int(user_id)
        tracking_data = load_tracking_data()
        tracking_data["tracked_user_id"] = user_id_int
        save_tracking_data(tracking_data)
        
        await interaction.response.send_message(f"now tracking user ID {user_id} as Lillian")
    except ValueError:
        await interaction.response.send_message("invalid user ID format", ephemeral=True)

@tree.command(name='lillianstatus', description='check if Lillian is currently in the server', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def lillian_status(interaction: discord.Interaction):
    tracking_data = load_tracking_data()
    
    if not tracking_data["tracked_user_id"]:
        await interaction.response.send_message("no user is currently being tracked", ephemeral=True)
        return
    
    # Check if user is in server
    guild = interaction.guild
    member = guild.get_member(tracking_data["tracked_user_id"])
    
    embed = discord.Embed(title="Lillian Status", color=0x3498db)
    
    if member:
        embed.color = 0x00ff00
        embed.add_field(name="Status", value="🟢 In Server", inline=True)
        if tracking_data["current_session"]:
            join_time = datetime.fromisoformat(tracking_data["current_session"]["join_time"].replace('Z', '+00:00'))
            duration = datetime.now(timezone.utc) - join_time
            days = duration.days
            hours, remainder = divmod(duration.seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            
            if days > 0:
                duration_str = f"{days} days, {hours} hours, {minutes} minutes"
            elif hours > 0:
                duration_str = f"{hours} hours, {minutes} minutes"
            else:
                duration_str = f"{minutes} minutes"
            
            embed.add_field(name="Current Session Duration", value=duration_str, inline=True)
            embed.add_field(name="Joined", value=f"<t:{int(join_time.timestamp())}:R>", inline=True)
    else:
        embed.color = 0xff0000
        embed.add_field(name="Status", value="🔴 Not in Server", inline=True)
    
    embed.add_field(name="Tracked User ID", value=str(tracking_data["tracked_user_id"]), inline=True)
    
    await interaction.response.send_message(embed=embed)

@tree.command(name='lillianleaderboard', description='show Lillian\'s server time leaderboard', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def lillian_leaderboard(interaction: discord.Interaction):
    tracking_data = load_tracking_data()
    
    if not tracking_data["leaderboard"]:
        await interaction.response.send_message("no leaderboard data available yet", ephemeral=True)
        return
    
    embed = discord.Embed(
        title="🏆 Lillian's Server Time Leaderboard",
        description="Longest to shortest server sessions",
        color=0xffd700
    )
    
    # Show top 10 entries
    for i, entry in enumerate(tracking_data["leaderboard"][:10], 1):
        join_time = datetime.fromisoformat(entry["join_time"].replace('Z', '+00:00'))
        leave_time = datetime.fromisoformat(entry["leave_time"].replace('Z', '+00:00'))
        
        medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"{i}."
        
        embed.add_field(
            name=f"{medal} Session {i}",
            value=f"**Duration:** {entry['duration']}\n"
                  f"**Joined:** <t:{int(join_time.timestamp())}:d>\n"
                  f"**Left:** <t:{int(leave_time.timestamp())}:d>",
            inline=True
        )
    
    total_sessions = len(tracking_data["leaderboard"])
    embed.set_footer(text=f"Total sessions recorded: {total_sessions}")
    
    await interaction.response.send_message(embed=embed)

@tree.command(name='cleartracking', description='clear all tracking data for Lillian', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def clear_tracking(interaction: discord.Interaction):
    tracking_data = {
        "tracked_user_id": None,
        "current_session": None,
        "leaderboard": []
    }
    save_tracking_data(tracking_data)
    await interaction.response.send_message("tracking data cleared")


@tree.command(name='importlillian', description='import tracking data from an exported embed', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def import_lillian(interaction: discord.Interaction, user_id: str, data_file: discord.Attachment):
    try:
        user_id_int = int(str(user_id))
    except ValueError:
        await interaction.response.send_message("invalid user id", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    try:
        raw_bytes = await data_file.read()
    except Exception as exc:
        logger.error("Failed to read uploaded migration file: %s", exc)
        await interaction.followup.send("could not read uploaded file", ephemeral=True)
        return

    try:
        text = raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        text = raw_bytes.decode('latin-1')

    try:
        leaderboard, current_session = parse_lillian_migration(text, user_id_int)
    except Exception as exc:
        logger.exception("Failed to parse migration data")
        await interaction.followup.send(f"failed to parse migration data: {exc}", ephemeral=False)
        return

    tracking_data = {
        "tracked_user_id": user_id_int,
        "current_session": current_session,
        "leaderboard": leaderboard,
    }
    save_tracking_data(tracking_data)
    logger.info("Imported %d leaderboard entries for user %s", len(leaderboard), user_id_int)
    await interaction.followup.send(
        f"imported {len(leaderboard)} sessions for lillian w/ user id {user_id_int}" + (
            " (current session active)" if current_session else ""
        ),
        ephemeral=True,
    )

# --- Updated Error Handler ---
@tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, NotOwnerError):
        # Custom message for non-owners
        await interaction.response.send_message('ew who are you you cant tell me what to do', ephemeral=False)
    elif isinstance(error, WrongChannelError):
        # Custom message for using the command in the wrong channel
        await interaction.response.send_message('this command cant be used here', ephemeral=True)
    elif isinstance(error, app_commands.CheckFailure):
        # Fallback for any other permission-related errors
        await interaction.response.send_message('ew who are you you cant tell me what to do', ephemeral=True)
    else:
        # Generic error for other issues
        await interaction.response.send_message('an error occurred', ephemeral=True)
        raise error

def resolve_bot_token():
    """Resolve the Discord bot token from environment variables or configuration."""
    token = os.getenv('BOT_TOKEN') or OPTIONS.get('bot_token')
    if not token:
        logger.error("BOT_TOKEN is not set. Provide it via environment variable or configuration file.")
        return None
    return token


# Get the token and run the bot
BOT_TOKEN = resolve_bot_token()

if BOT_TOKEN:
    bot.run(BOT_TOKEN)
else:
    logger.error("Bot could not be started due to a token configuration error.")
