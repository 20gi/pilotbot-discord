import discord
from discord import app_commands
from discord.ext import commands
import aiohttp

# Bot setup
intents = discord.Intents.default()
bot = commands.Bot(command_prefix='!', intents=intents)

# --- Control Server and Channel IDs ---
CONTROL_SERVER_ID = 1258526802599481375
CONTROL_CHANNEL_ID = 1311918837528002600
CONTROL_GUILD = discord.Object(id=CONTROL_SERVER_ID)
# ------------------------------------

# Command Tree for slash commands
tree = bot.tree

print("updated!!")

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

# Custom check to verify the user is the bot owner AND in the correct channel
def is_owner_and_in_control_channel():
    def predicate(interaction: discord.Interaction) -> bool:
        # Check if the bot's owner_id has been set
        if bot.owner_id is None:
            return False
        
        # Check if the user is the owner AND is in the control channel
        is_owner = interaction.user.id == bot.owner_id
        is_control_channel = interaction.channel_id == CONTROL_CHANNEL_ID
        
        return is_owner and is_control_channel
    return app_commands.check(predicate)

@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')
    
    # Fetch and set the bot owner's ID
    app_info = await bot.application_info()
    bot.owner_id = app_info.owner.id
    print(f"Owner ID set to: {bot.owner_id}")

    # Sync the slash commands to the control server
    await tree.sync(guild=CONTROL_GUILD)
    print(f"Synced slash commands for guild: {CONTROL_SERVER_ID}")

    # Set the bot's status
    await bot.change_presence(
        status=discord.Status.online,
        activity=discord.Activity(type=discord.ActivityType.watching, name="i hate dusekkar")
    )
    print("Status set to: Watching i hate dusekkar")

# Command to update bio
@tree.command(name='updatebio', description='update the bot bio (owner only)', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def update_bio_command(interaction: discord.Interaction, new_bio: str):
    """Command to update bot bio"""
    await interaction.response.defer() 
    await update_bot_bio(new_bio)
    await interaction.followup.send(f"bio updated to: {new_bio}")

# Command to change status
@tree.command(name='setstatus', description='change the bot\'s activity status (owner only)', guild=CONTROL_GUILD)
@app_commands.choices(status_type=[
    app_commands.Choice(name='Playing', value='playing'),
    app_commands.Choice(name='Watching', value='watching'),
    app_commands.Choice(name='Listening to', value='listening'),
    app_commands.Choice(name='Streaming', value='streaming'),
    app_commands.Choice(name='Competing in', value='competing'),
])
@is_owner_and_in_control_channel()
async def set_status_command(interaction: discord.Interaction, status_type: app_commands.Choice[str], status_text: str):
    """Command to change bot status"""
    status_map = {
        'playing': discord.ActivityType.playing,
        'watching': discord.ActivityType.watching,
        'listening': discord.ActivityType.listening,
        'streaming': discord.ActivityType.streaming,
        'competing': discord.ActivityType.competing
    }
    
    activity = discord.Activity(type=status_map[status_type.value], name=status_text)
    await bot.change_presence(status=discord.Status.online, activity=activity)
    
    await interaction.response.send_message(f"status changed to: {status_type.name} {status_text}")

# Command to set online status
@tree.command(name='setonline', description='change the bot\'s online status (owner only)', guild=CONTROL_GUILD)
@app_commands.choices(online_status=[
    app_commands.Choice(name='Online', value='online'),
    app_commands.Choice(name='Idle', value='idle'),
    app_commands.Choice(name='Do Not Disturb', value='dnd'),
    app_commands.Choice(name='Invisible', value='invisible'),
])
@is_owner_and_in_control_channel()
async def set_online_status(interaction: discord.Interaction, online_status: app_commands.Choice[str]):
    """Command to change online status"""
    status_map = {
        'online': discord.Status.online,
        'idle': discord.Status.idle,
        'dnd': discord.Status.dnd,
        'invisible': discord.Status.invisible,
    }

    current_activity = interaction.guild.me.activity
    await bot.change_presence(status=status_map[online_status.value], activity=current_activity)
    
    await interaction.response.send_message(f"status changed to: {online_status.name}")

# Command to clear status
@tree.command(name='clearstatus', description='clear the bot\'s activity status (owner only)', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def clear_status_command(interaction: discord.Interaction):
    """Command to clear the bot's activity status"""
    await bot.change_presence(status=discord.Status.online, activity=None)
    await interaction.response.send_message("status cleared")

# Error handler for slash commands
@tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    # This will catch failures from the is_owner_and_in_control_channel check
    if isinstance(error, app_commands.CheckFailure):
        await interaction.response.send_message('you do not have permission to use this command here', ephemeral=True)
    else:
        await interaction.response.send_message('an error occurred', ephemeral=True)
        # Also print the error to the console for debugging
        raise error

# Replace 'YOUR_BOT_TOKEN' with your actual bot token
bot.run('MTM5NzgxNzcxMzkzMzY4NDgyNw.GwogIJ.ZwYkFNa4_upJ7n4m87gv5NxPTRuXOvBOVaOT60')