import discord
from discord import app_commands
from discord.ext import commands
import aiohttp
import os
import json

# Bot setup
intents = discord.Intents.default()
bot = commands.Bot(command_prefix='!', intents=intents)
CONFIG_PATH = '/data/options.json'

# --- Control Server and Channel IDs ---
CONTROL_SERVER_ID = 1258526802599481375
CONTROL_CHANNEL_ID = 1311918837528002600
CONTROL_GUILD = discord.Object(id=CONTROL_SERVER_ID)
# ------------------------------------

# Command Tree for slash commands
tree = bot.tree

print("updated!!")

# --- Custom Exceptions for Error Handling ---
class NotOwnerError(app_commands.CheckFailure):
    """Exception raised when a command is used by a non-owner."""
    pass

class WrongChannelError(app_commands.CheckFailure):
    """Exception raised when a command is used in the wrong channel."""
    pass
# -----------------------------------------

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

    await tree.sync(guild=CONTROL_GUILD)
    print(f"Synced slash commands for guild: {CONTROL_SERVER_ID}")

    await bot.change_presence(
        status=discord.Status.online,
        activity=discord.Activity(type=discord.ActivityType.watching, name="i hate dusekkar")
    )
    print("Status set to: Watching i hate dusekkar")

# --- Bot Commands ---
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
    status_map = {
        'playing': discord.ActivityType.playing, 'watching': discord.ActivityType.watching,
        'listening': discord.ActivityType.listening, 'streaming': discord.ActivityType.streaming,
        'competing': discord.ActivityType.competing
    }
    activity = discord.Activity(type=status_map[status_type.value], name=status_text)
    await bot.change_presence(status=discord.Status.online, activity=activity)
    await interaction.response.send_message(f"status changed to: {status_type.name} {status_text}")

@tree.command(name='setonline', description='change the bot\'s online status', guild=CONTROL_GUILD)
@app_commands.choices(online_status=[
    app_commands.Choice(name='Online', value='online'), app_commands.Choice(name='Idle', value='idle'),
    app_commands.Choice(name='Do Not Disturb', value='dnd'), app_commands.Choice(name='Invisible', value='invisible'),
])
@is_owner_and_in_control_channel()
async def set_online_status(interaction: discord.Interaction, online_status: app_commands.Choice[str]):
    status_map = {
        'online': discord.Status.online, 'idle': discord.Status.idle,
        'dnd': discord.Status.dnd, 'invisible': discord.Status.invisible,
    }
    current_activity = interaction.guild.me.activity
    await bot.change_presence(status=status_map[online_status.value], activity=current_activity)
    await interaction.response.send_message(f"status changed to: {online_status.name}")

@tree.command(name='clearstatus', description='clear the bot\'s activity status', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def clear_status_command(interaction: discord.Interaction):
    await bot.change_presence(status=discord.Status.online, activity=None)
    await interaction.response.send_message("status cleared")

# --- Updated Error Handler ---
@tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, NotOwnerError):
        # Custom message for non-owners
        await interaction.response.send_message('you dont have permission haha pilot on top', ephemeral=True)
    elif isinstance(error, WrongChannelError):
        # Custom message for using the command in the wrong channel
        await interaction.response.send_message('this command cant be used here', ephemeral=True)
    elif isinstance(error, app_commands.CheckFailure):
        # Fallback for any other permission-related errors
        await interaction.response.send_message('you do not have permission to use this command', ephemeral=True)
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