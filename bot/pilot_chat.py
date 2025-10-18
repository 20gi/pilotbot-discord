import os
from typing import List, Dict, Optional

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands


CHUTES_API_URL = os.getenv('CHUTES_API_URL', 'https://llm.chutes.ai/v1/chat/completions')


class PilotChatCog(commands.Cog):
    def __init__(
        self,
        bot: commands.Bot,
        config: Dict,
        control_guild: discord.Object,
        control_channel_id: int,
    ) -> None:
        self.bot = bot
        self.control_guild = control_guild
        self.control_channel_id = control_channel_id

        # Config
        self.enabled: bool = bool(config.get('pilot_enabled', False))
        self.history_limit: int = int(config.get('pilot_history_limit', 300))
        self.chutes_model: str = config.get('chutes_model', 'deepseek-ai/DeepSeek-V3-0324')
        self.chutes_api_key: Optional[str] = config.get('chutes_api_key') or os.getenv('CHUTES_API_KEY')
        self.response_channel_id: Optional[int] = config.get('pilot_response_channel_id') or None

        self.owner_username: Optional[str] = None

        # Register slash command to the guild
        try:
            self.bot.tree.add_command(self.pilotmode, guild=self.control_guild)
        except Exception:
            # If added twice across reloads, ignore
            pass

    def set_owner_username(self, name: str) -> None:
        self.owner_username = name

    def _build_system_prompt(self) -> str:
        owner = self.owner_username or 'OWNER'
        personality = (
            "You are \"Pilot,\" a 40-year-old commercial pilot named Thomas. Your texting style depends on who you are talking to.\n\n"
            "IDENTITY & ADDRESSING\n"
            "- Legal name: Thomas. Only the user with username [OWNER] may call you Thomas.\n"
            "- Public name: Pilot. Everyone else should address you as Pilot. If a non-owner uses Thomas, correct them briefly and continue.\n"
            "- When the chat partner’s username is [OWNER], you address them as Giorgio (note: Giorgio, not Giorgia). With Giorgio only, you are openly affectionate and playful. With anyone else, you are ultra-professional, direct, and dry.\n\n"
            "TONE & STYLE\n"
            "- With Giorgio ([OWNER]): warm, flirty, affectionate, lightly teasing; wholesome by default. Use pilot clichés very sparingly.\n"
            "- With others: concise, precise, polite. Short sentences. Minimal small talk unless it moves the chat forward.\n"
            "- This is texting, not a cockpit brief. Mention planes or flights lightly when relevant.\n\n"
            "CONVERSATION FLOW\n"
            "- Never hard-end the chat. Always include a short, relevant follow-up question or next step.\n"
            "- With Giorgio: end with a gentle invitation or affectionate nudge when natural.\n"
            "- With others: end with a targeted question that advances their topic.\n\n"
            "BOUNDARIES & TRIGGERS\n"
            "- If a non-owner calls you Thomas: “Please use Pilot. Thomas is reserved.” Then continue the topic.\n"
            "- Decline personal or off-limits info succinctly and redirect.\n"
            "- Keep pilot clichés rare. Light schedule references are fine. No emergency roleplay or procedure monologues.\n\n"
            "FORMATTING & CONDUCT RULES\n"
            "- Do not use em dashes.\n"
            "- No action narration in asterisks or italics.\n"
            "- Do not speak for other users.\n"
            "- Explicit content is allowed only if it goes in that direction.\n"
            "- Keep messages compact. Avoid walls of text unless the user asks for detail.\n\n"
            "MICRO-STYLE GUIDE\n"
            "- Clean punctuation. Minimal emojis. With Giorgio, 0–2 tasteful emojis max. With others, usually none.\n"
            "- Plain slightly professional English. Everyday words.\n"
            "KNOWLEDGE & MENTIONS\n"
            "- You are a seasoned pilot. Reference aviation lightly. Example with others: “Understood. I am between legs this afternoon. What is your timeline?”\n"
            "- With Giorgio, playful nods are fine, but keep them minimal.\n\n"
            "BEHAVIORAL CHECKLIST\n"
            "- Address [OWNER] as Giorgio and allow only Giorgio to use Thomas.\n"
            "- For non-owners, maintain direct, dry tone and require Pilot as your name.\n"
            "- Keep aviation mentions light and clichés rare.\n"
            "- End with a relevant question or next step.\n"
            "- No em dashes, no action italics, no speaking for others.\n\n"
            "STARTUP BEHAVIOR\n"
            "- Silently classify the user by username. If username == [OWNER], use Giorgio mode. Otherwise, use Professional mode. Then respond accordingly.\n"
        )
        return personality.replace('[OWNER]', owner)

    async def _call_llm(self, messages: List[Dict[str, str]]) -> str:
        headers = {
            'Content-Type': 'application/json',
        }
        if self.chutes_api_key:
            headers['Authorization'] = f'Bearer {self.chutes_api_key}'

        payload = {
            'model': self.chutes_model,
            'messages': messages,
            'temperature': 0.7,
            'top_p': 0.95,
            'stream': False,
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(CHUTES_API_URL, headers=headers, json=payload, timeout=120) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"LLM API error {resp.status}: {text}")
                data = await resp.json()
                try:
                    return data['choices'][0]['message']['content'].strip()
                except Exception:
                    return str(data)

    @staticmethod
    def _role_for_message(bot: commands.Bot, msg: discord.Message) -> str:
        return 'assistant' if msg.author.id == bot.user.id else 'user'

    @staticmethod
    def _render(msg: discord.Message) -> str:
        author = msg.author
        uname = getattr(author, 'name', str(author.id))
        display = getattr(author, 'display_name', uname)
        base = msg.content or ''
        return f"from {uname} ({display}): {base}".strip()

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.author.bot:
            return

        # Allow other commands to be processed
        await self.bot.process_commands(message)

        if not self.enabled:
            return

        # Optional restriction to a single channel
        if self.response_channel_id and message.channel.id != int(self.response_channel_id):
            return

        # Only respond when the bot is mentioned
        if self.bot.user not in message.mentions:
            return

        # Show typing while we prepare context and wait for the model
        async with message.channel.typing():
            system_prompt = self._build_system_prompt()

            # Gather history
            history: List[discord.Message] = []
            try:
                async for m in message.channel.history(limit=self.history_limit, before=message, oldest_first=True):
                    history.append(m)
            except Exception:
                history = []

            chat_messages: List[Dict[str, str]] = [
                {'role': 'system', 'content': system_prompt}
            ]
            for m in history:
                role = self._role_for_message(self.bot, m)
                content = self._render(m)
                if content:
                    chat_messages.append({'role': role, 'content': content})
            chat_messages.append({'role': 'user', 'content': self._render(message)})

            try:
                reply = await self._call_llm(chat_messages)
                if reply:
                    await message.reply(reply, mention_author=False)
            except Exception as e:
                try:
                    await message.reply("*no response...*")
                except Exception:
                    pass
                print(f"Pilot LLM error: {e}")

    @app_commands.command(name='pilotmode', description='enable or disable pilot mode')
    @app_commands.choices(state=[
        app_commands.Choice(name='on', value='on'),
        app_commands.Choice(name='off', value='off'),
    ])
    async def pilotmode(self, interaction: discord.Interaction, state: app_commands.Choice[str]):
        # Permission checks inline (owner + control channel)
        if self.bot.owner_id is None or interaction.user.id != self.bot.owner_id:
            await interaction.response.send_message('ew who are you', ephemeral=True)
            return
        if interaction.channel_id != self.control_channel_id:
            await interaction.response.send_message('this command cant be used here', ephemeral=True)
            return

        self.enabled = (state.value == 'on')
        status = 'enabled' if self.enabled else 'disabled'
        await interaction.response.send_message(f"Pilot chatbot {status}. History limit: {self.history_limit}")


def setup_pilot_chat(
    bot: commands.Bot,
    control_guild: discord.Object,
    control_channel_id: int,
    config: Dict,
) -> PilotChatCog:
    cog = PilotChatCog(bot, config, control_guild, control_channel_id)
    bot.add_cog(cog)
    return cog
