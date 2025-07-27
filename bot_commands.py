# bot_commands.py

import discord
from discord import app_commands
from discord.ext import commands

# --- Custom Exceptions for Error Handling ---
class NotOwnerError(app_commands.CheckFailure):
    """Exception raised when a command is used by a non-owner."""
    pass

class WrongChannelError(app_commands.CheckFailure):
    """Exception raised when a command is used in the wrong channel."""
    pass

# The main Cog class for control commands
class ControlCog(commands.Cog):
    def __init__(self, bot: commands.Bot, config: dict):
        self.bot = bot
        self.config = config
        self.CONTROL_GUILD = discord.Object(id=int(config['control_server_id']))
        self.BOT_OWNER_ID = int(config['bot_owner_id'])
        self.CONTROL_CHANNEL_ID = int(config['control_channel_id'])

    # Custom check that raises specific errors for different failures
    def is_owner_and_in_control_channel(self):
        async def predicate(interaction: discord.Interaction) -> bool:
            # First, check if the user is the bot owner defined in the config
            if interaction.user.id != self.BOT_OWNER_ID:
                raise NotOwnerError()

            # If they are the owner, then check if they are in the right channel
            if interaction.channel_id != self.CONTROL_CHANNEL_ID:
                raise WrongChannelError()
                
            # If both checks pass, allow the command
            return True
        return app_commands.check(predicate)

    # --- Bot Commands ---
    # NOTE: The update_bot_bio function is in the main bot.py file
    # so it can be shared with the web UI. We call it from here.
    @app_commands.command(name='updatebio', description='update the bot bio')
    @is_owner_and_in_control_channel()
    async def update_bio_command(self, interaction: discord.Interaction, new_bio: str):
        await interaction.response.defer(ephemeral=True)
        # We need to access the update_bot_bio function from the main bot instance
        if hasattr(self.bot, 'update_bot_bio_from_cog'):
            success = await self.bot.update_bot_bio_from_cog(new_bio)
            if success:
                await interaction.followup.send(f"bio updated to: {new_bio}")  # not ephemeral
            else:
                await interaction.followup.send("Failed to update bio.", ephemeral=True)
        else:
            await interaction.followup.send("Error: Bio update function not found.", ephemeral=True)


    @app_commands.command(name='setstatus', description="change the bot's activity status")
    @app_commands.choices(status_type=[
        app_commands.Choice(name='Playing', value='playing'),
        app_commands.Choice(name='Watching', value='watching'),
        app_commands.Choice(name='Listening to', value='listening'),
        app_commands.Choice(name='Streaming', value='streaming'),
        app_commands.Choice(name='Competing in', value='competing'),
    ])
    @is_owner_and_in_control_channel()
    async def set_status_command(self, interaction: discord.Interaction, status_type: app_commands.Choice[str], status_text: str):
        status_map = {
            'playing': discord.ActivityType.playing, 'watching': discord.ActivityType.watching,
            'listening': discord.ActivityType.listening, 'streaming': discord.ActivityType.streaming,
            'competing': discord.ActivityType.competing
        }
        activity = discord.Activity(type=status_map[status_type.value], name=status_text)
        await self.bot.change_presence(status=discord.Status.online, activity=activity)
        await interaction.response.send_message(f"Status changed to: {status_type.name} {status_text}")  # not ephemeral

    @app_commands.command(name='setonline', description="change the bot's online status")
    @app_commands.choices(online_status=[
        app_commands.Choice(name='Online', value='online'), app_commands.Choice(name='Idle', value='idle'),
        app_commands.Choice(name='Do Not Disturb', value='dnd'), app_commands.Choice(name='Invisible', value='invisible'),
    ])
    @is_owner_and_in_control_channel()
    async def set_online_status(self, interaction: discord.Interaction, online_status: app_commands.Choice[str]):
        status_map = {
            'online': discord.Status.online, 'idle': discord.Status.idle,
            'dnd': discord.Status.dnd, 'invisible': discord.Status.invisible,
        }
        # Get current activity to preserve it when changing online status
        current_activity = interaction.guild.me.activity if interaction.guild else None
        await self.bot.change_presence(status=status_map[online_status.value], activity=current_activity)
        await interaction.response.send_message(f"Online status changed to: {online_status.name}")  # not ephemeral

    @app_commands.command(name='clearstatus', description="clear the bot's activity status")
    @is_owner_and_in_control_channel()
    async def clear_status_command(self, interaction: discord.Interaction):
        await self.bot.change_presence(status=discord.Status.online, activity=None)
        await interaction.response.send_message("Status cleared")  # not ephemeral

    # --- Cog-level Error Handler ---
    async def cog_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        if isinstance(error, NotOwnerError):
            await interaction.response.send_message('You do not have permission to use this command.', ephemeral=True)
        elif isinstance(error, WrongChannelError):
            await interaction.response.send_message('This command cannot be used in this channel.', ephemeral=True)
        elif isinstance(error, app_commands.CheckFailure):
            await interaction.response.send_message('You do not have permission to use this command.', ephemeral=True)
        else:
            await interaction.response.send_message('An unexpected error occurred.', ephemeral=True)
            # It's good practice to log the actual error for debugging
            print(f"Unhandled error in ControlCog: {error}")


# This setup function is required for the bot to load the Cog
async def setup(bot: commands.Bot):
    # Pass the bot's config to the Cog
    await bot.add_cog(ControlCog(bot, bot.config), guilds=[discord.Object(id=int(bot.config['control_server_id']))])