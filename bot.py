import discord
from discord.ext import commands
import aiohttp

# Bot setup
intents = discord.Intents.default()
bot = commands.Bot(command_prefix='!', intents=intents)

async def update_bot_bio(bio_text):
    """Update the bot's About Me section"""
    url = "https://discord.com/api/v10/applications/@me"
    headers = {
        "Authorization": f"Bot {bot.http.token}",
        "Content-Type": "application/json"
    }
    data = {
        "description": bio_text
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.patch(url, json=data, headers=headers) as response:
            if response.status == 200:
                print(f"Successfully updated bot bio to: {bio_text}")
            else:
                print(f"Failed to update bio: {response.status}")
                error_text = await response.text()
                print(f"Error: {error_text}")

@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')
    
    # Set the bot's status to "Watching nothing"
    await bot.change_presence(
        status=discord.Status.online,
        activity=discord.Activity(type=discord.ActivityType.watching, name="i hate dusekkar")
    )
    print("Status set to: Watching nothing")
    
    # Update the bot's About Me section

# Define the specific server and channel for responses
CONTROL_SERVER_ID = 1258526802599481375
CONTROL_CHANNEL_ID = 1311918837528002600

async def send_response(message):
    """Send response to the specific channel"""
    channel = bot.get_channel(CONTROL_CHANNEL_ID)
    if channel:
        await channel.send(message)
    else:
        print(f"Could not find channel {CONTROL_CHANNEL_ID}")

def is_owner_in_control_channel():
    """Custom check to ensure command is from owner and will respond in control channel"""
    async def predicate(ctx):
        return await bot.is_owner(ctx.author)
    return commands.check(predicate)

# Command to update bio (optional)
@bot.command(name='updatebio')
@is_owner_in_control_channel()
async def update_bio_command(ctx, *, new_bio):
    """Command to update bot bio (only bot owner can use this)"""
    await update_bot_bio(new_bio)
    await send_response(f"bio updated to: {new_bio}")

# Command to change status
@bot.command(name='setstatus')
@is_owner_in_control_channel()
async def set_status_command(ctx, status_type, *, status_text):
    """
    Command to change bot status
    Usage: !setstatus <type> <text>
    Types: playing, watching, listening, streaming, competing
    Example: !setstatus watching Netflix
    """
    status_type = status_type.lower()
    
    # Map status types to Discord ActivityType
    status_map = {
        'playing': discord.ActivityType.playing,
        'watching': discord.ActivityType.watching,
        'listening': discord.ActivityType.listening,
        'streaming': discord.ActivityType.streaming,
        'competing': discord.ActivityType.competing
    }
    
    if status_type not in status_map:
        await send_response("invalid type... types: playing, watching, listening, streaming, or competing")
        return
    
    # Set the new status
    activity = discord.Activity(type=status_map[status_type], name=status_text)
    await bot.change_presence(status=discord.Status.online, activity=activity)
    
    await send_response(f"status changed to: {status_type.title()} {status_text}")

# Command to set online status (online, idle, dnd, invisible)
@bot.command(name='setonline')
@is_owner_in_control_channel()
async def set_online_status(ctx, online_status):
    """
    Command to change online status
    Usage: !setonline <status>
    Status options: online, idle, dnd, invisible
    """
    online_status = online_status.lower()
    
    status_map = {
        'online': discord.Status.online,
        'idle': discord.Status.idle,
        'dnd': discord.Status.dnd,
        'do_not_disturb': discord.Status.dnd,
        'invisible': discord.Status.invisible,
        'offline': discord.Status.invisible
    }
    
    if online_status not in status_map:
        await send_response("invalid status. status types: online, idle, dnd, or invisible")
        return
    
    # Keep current activity but change online status
    current_activity = bot.activity
    await bot.change_presence(status=status_map[online_status], activity=current_activity)
    
    await send_response(f"status changed to: {online_status}")

# Command to clear status (remove activity)
@bot.command(name='clearstatus')
@is_owner_in_control_channel()
async def clear_status_command(ctx):
    """Command to clear the bot's activity status"""
    await bot.change_presence(status=discord.Status.online, activity=None)
    await send_response("status cleared")

# Replace 'YOUR_BOT_TOKEN' with your actual bot token
bot.run('MTM5NzgxNzcxMzkzMzY4NDgyNw.GwogIJ.ZwYkFNa4_upJ7n4m87gv5NxPTRuXOvBOVaOT60')
