import discord
import logging
from discord import app_commands
from discord.ext import commands
import aiohttp
import os
import json
from datetime import datetime, timezone
import asyncio
import yaml
from pilot_chat import setup_pilot_chat

# silly messages version
# Bot setup
intents = discord.Intents.default()
intents.members = True  # Required for member join/leave events
intents.presences = True  # Required for tracking owner's presence
intents.message_content = True  # Required for reading messages to build history
bot = commands.Bot(command_prefix='!', intents=intents)
CONFIG_PATH = '/data/options.json'
TRACKING_DATA_PATH = '/data/lillian_tracking.json'

# --- Pilot Chat Cog holder ---
PILOT_COG = None

# --- Control Server and Channel IDs ---
CONTROL_SERVER_ID = 1258526802599481375
CONTROL_CHANNEL_ID = 1311918837528002600
MONITORING_CHANNEL_ID = 1399788089307566111
CONTROL_GUILD = discord.Object(id=CONTROL_SERVER_ID)
# ------------------------------------

# Command Tree for slash commands
tree = bot.tree

print("updated!!")

# Configure basic logging if not already configured (HA addons often have none)
if not logging.getLogger().hasHandlers():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')

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
        with open(TRACKING_DATA_PATH, 'r') as f:
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
        print(f"Error: Could not decode JSON from {TRACKING_DATA_PATH}")
        return {"tracked_user_id": None, "current_session": None, "leaderboard": []}

def save_tracking_data(data):
    """Save tracking data to JSON file"""
    try:
        with open(TRACKING_DATA_PATH, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving tracking data: {e}")

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
            print(f"Monitoring channel {MONITORING_CHANNEL_ID} not found")
    except Exception as e:
        print(f"Error sending monitoring message: {e}")

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
        print(f"Owner went offline, setting bot to invisible")
        # Store current activity before going offline
        if bot.user:
            guild = bot.get_guild(CONTROL_SERVER_ID)
            if guild and guild.me:
                bot_original_activity = guild.me.activity
        
        await bot.change_presence(status=discord.Status.invisible, activity=None)
        bot_was_manually_set_offline = False
        
    # Check if owner came back online
    elif before.status == discord.Status.offline and after.status != discord.Status.offline:
        print(f"Owner came online, setting bot back to online")
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
                print(f"Successfully updated bot bio to: {bio_text}")
            else:
                print(f"Failed to update bio: {response.status}")
                error_text = await response.text()
                print(f"Error: {error_text}")

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
    print(f'{bot.user} has connected to Discord!')
    
    app_info = await bot.application_info()
    bot.owner_id = app_info.owner.id
    print(f"Owner ID set to: {bot.owner_id}")

    # Setup Pilot Chat cog using Home Assistant options first, fallback to config.yaml
    def _load_options():
        # Primary: Home Assistant passes options to /data/options.json
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f) or {}
            return data
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Failed to load {CONFIG_PATH}: {e}")

        # Fallback: local dev via config.yaml
        try:
            with open('config.yaml', 'r', encoding='utf-8') as f:
                y = yaml.safe_load(f) or {}
            return y.get('options', {})
        except FileNotFoundError:
            return {}
        except Exception as e:
            print(f"Failed to load config.yaml: {e}")
            return {}

    options = _load_options()
    # Parse channel id safely from string to avoid precision loss
    raw_channel = options.get('pilot_response_channel_id')
    parsed_channel = None
    if raw_channel not in (None, "", 0, "0"):
        try:
            parsed_channel = int(str(raw_channel))
        except Exception as e:
            print(f"Invalid pilot_response_channel_id '{raw_channel}': {e}")

    pilot_config = {
        'pilot_enabled': bool(options.get('pilot_enabled', False)),
        'pilot_history_limit': int(options.get('pilot_history_limit', 300)),
        'chutes_model': options.get('chutes_model', 'deepseek-ai/DeepSeek-V3-0324'),
        'chutes_api_key': options.get('chutes_api_key') or os.getenv('CHUTES_API_KEY'),
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
            print(f"Chutes API key: {key_to_show}")
        else:
            print(f"Chutes API key (masked): {_mask_key(key_to_show)} — set CHUTES_PRINT_FULL_KEY=1 to show full key")
    else:
        print("Chutes API key not set")

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
    print(f"Synced slash commands for guild: {CONTROL_SERVER_ID}")

    await bot.change_presence(
        status=discord.Status.online,
        activity=discord.Activity(type=discord.ActivityType.watching, name="i hate dusekkar")
    )
    print("Status set to: Watching i hate dusekkar")

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

def get_token_from_config():
    """Reads the bot token from the Home Assistant options.json file."""
    try:
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        token = config.get('bot_token')
        if not token:
            print("Error: 'bot_token' not found in the configuration file.")
            return None
        return token
    except FileNotFoundError:
        print(f"Error: Configuration file not found at {CONFIG_PATH}")
        return None
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {CONFIG_PATH}")
        return None

# Get the token and run the bot
BOT_TOKEN = get_token_from_config()

if BOT_TOKEN:
    bot.run(BOT_TOKEN)
else:
    print("Bot could not be started due to a token configuration error.")
