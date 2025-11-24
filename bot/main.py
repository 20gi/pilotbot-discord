import discord
import logging
from discord import app_commands
from discord.ext import commands
import aiohttp
import os
import json
import re
import secrets
import string
from datetime import datetime, timezone
import asyncio
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
import yaml
from pilot_chat import setup_pilot_chat
import ssl
from web_api import start_web_server, DEFAULT_WEB_PORT

logger = logging.getLogger(__name__)

# --- Configuration loading -------------------------------------------------
DEFAULT_CONFIG_FILE = os.getenv('BOT_CONFIG_FILE')
DEFAULT_DATA_DIR = Path(os.getenv('DATA_DIR', 'data'))
ALLOWED_USERS_FILE = DEFAULT_DATA_DIR / 'web_allowed_users.json'
THEME_SETTINGS_FILE = DEFAULT_DATA_DIR / 'web_theme.json'


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


def _clean_env(value):
    if value is None:
        return None
    if isinstance(value, str) and value.strip() == '':
        return None
    return value


def _read_secret_file(path: str | None) -> str | None:
    if not path:
        return None
    try:
        data = Path(path).read_text(encoding='utf-8').strip()
        return data or None
    except Exception as exc:
        logger.warning("Failed to read secret file %s: %s", path, exc)
        return None


def _normalize_path_input(value) -> str | None:
    """Normalize a potential path input into a stripped string or None."""
    if value is None:
        return None
    if isinstance(value, Path):
        text = str(value)
    else:
        text = str(value)
    text = text.strip()
    return text or None


def _resolve_tracking_data_path(option_value, env_value, data_dir: Path):
    """Resolve the tracking data path and return (path, details, log_messages)."""
    logs: List[tuple[int, str]] = []

    option_text = _normalize_path_input(option_value)
    env_text = _normalize_path_input(env_value)
    logs.append((logging.INFO, f"TRACKING_DATA_PATH inputs -> option={option_text!r}, env={env_text!r}"))

    chosen_text = option_text or env_text
    source = 'default'

    if chosen_text is None:
        path = data_dir / 'lillian_tracking.json'
        logs.append((logging.INFO, f"No tracking data path configured; using default file {path}"))
    else:
        candidate = Path(chosen_text).expanduser()
        source = 'options' if option_text else 'env'
        treat_as_directory = False
        directory_base = candidate

        if chosen_text in {'.', os.curdir}:
            treat_as_directory = True
            logs.append(
                (logging.WARNING,
                 f"TRACKING_DATA_PATH '{chosen_text}' refers to the current directory; writing to "
                 f"{(directory_base / 'lillian_tracking.json')}")
            )
        elif chosen_text.endswith(('/', '\\')):
            treat_as_directory = True
            logs.append(
                (logging.WARNING,
                 f"TRACKING_DATA_PATH '{chosen_text}' ends with a path separator; treating it as directory "
                 f"{directory_base}")
            )
        elif candidate.exists() and candidate.is_dir():
            treat_as_directory = True
            logs.append(
                (logging.WARNING,
                 f"TRACKING_DATA_PATH '{candidate}' is a directory; defaulting to a file within it")
            )

        if treat_as_directory:
            path = directory_base / 'lillian_tracking.json'
        else:
            path = candidate

    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    logs.append((logging.INFO, f"TRACKING_DATA_PATH resolved (source={source}) -> {path.resolve()}"))

    details = {
        'option': option_text,
        'env': env_text,
        'source': source,
    }
    return path, details, logs


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
        'bot_token': _clean_env(os.getenv('BOT_TOKEN')),
        'chutes_api_key': _clean_env(os.getenv('CHUTES_API_KEY')),
        'chutes_model': _clean_env(os.getenv('CHUTES_MODEL')),
        'pilot_history_limit': _parse_int(os.getenv('PILOT_HISTORY_LIMIT')),
        'pilot_response_channel_id': _clean_env(os.getenv('PILOT_RESPONSE_CHANNEL_ID')),
        'pilot_enabled': _parse_bool(os.getenv('PILOT_ENABLED')),
        'pilot_style_mode': _clean_env(os.getenv('PILOT_STYLE_MODE')),
        'web_port': _parse_int(os.getenv('WEB_PORT')),
        'web_ssl_cert_path': _clean_env(os.getenv('WEB_SSL_CERT_PATH')),
        'web_ssl_key_path': _clean_env(os.getenv('WEB_SSL_KEY_PATH')),
        'web_auth_token': _clean_env(os.getenv('WEB_AUTH_TOKEN')),
        'web_oauth_client_id': _clean_env(os.getenv('WEB_OAUTH_CLIENT_ID')),
        'web_oauth_client_secret': _clean_env(os.getenv('WEB_OAUTH_CLIENT_SECRET')),
        'web_oauth_redirect_uri': _clean_env(os.getenv('WEB_OAUTH_REDIRECT_URI')),
        'web_session_secret': _clean_env(os.getenv('WEB_SESSION_SECRET')),
        'web_allowed_users': _clean_env(os.getenv('WEB_ALLOWED_USERS')),
        'control_server_id': _parse_int(os.getenv('CONTROL_SERVER_ID')),
        'control_channel_id': _parse_int(os.getenv('CONTROL_CHANNEL_ID')),
        'monitoring_channel_id': _parse_int(os.getenv('MONITORING_CHANNEL_ID')),
        'web_activity_channel_id': _parse_int(os.getenv('WEB_ACTIVITY_CHANNEL_ID')),
        'tracking_data_path': _clean_env(os.getenv('TRACKING_DATA_PATH')),
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
    for key in ('control_server_id', 'control_channel_id', 'monitoring_channel_id', 'web_activity_channel_id'):
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

TRACKING_DATA_PATH, TRACKING_DATA_PATH_DETAILS, TRACKING_PATH_LOGS = _resolve_tracking_data_path(
    OPTIONS.get('tracking_data_path'),
    os.getenv('TRACKING_DATA_PATH'),
    DATA_DIR,
)

# --- Discord bot setup -----------------------------------------------------
intents = discord.Intents.default()
intents.members = True  # Required for member join/leave events
intents.presences = True  # Required for tracking owner's presence
intents.message_content = True  # Required for reading messages to build history
# Remove legacy '!' prefix commands; keep only mention (for safety)
bot = commands.Bot(command_prefix=commands.when_mentioned, intents=intents)

# --- Pilot Chat Cog holder ---
PILOT_COG = None


def _int_with_default(key: str, default: int) -> int:
    value = _parse_int(OPTIONS.get(key)) if key in OPTIONS else None
    return value if value is not None else default


# --- Control Server and Channel IDs ---
CONTROL_SERVER_ID = _int_with_default('control_server_id', 1258526802599481375)
CONTROL_CHANNEL_ID = _int_with_default('control_channel_id', 1311918837528002600)
MONITORING_CHANNEL_ID = _int_with_default('monitoring_channel_id', 1399788089307566111)
# Optional channel for website activity logs (no fallback to monitoring)
WEB_ACTIVITY_CHANNEL_ID = _parse_int(OPTIONS.get('web_activity_channel_id'))
CONTROL_GUILD = discord.Object(id=CONTROL_SERVER_ID)
# ------------------------------------

# Holding account / secret sharing settings
HOLDING_ACCOUNT_SECRET_FILE = TRACKING_DATA_PATH.parent / 'holding_account_secret.json'
HOLDING_ACCOUNT_PASSWORD_LENGTH = 32
HOLDING_ACCOUNT_MODULUS = 20324  # 020324 as requested
HOLDING_ACCOUNT_SHARE_COUNT = 4
HOLDING_ACCOUNT_ROLE_ID = 1397084107103670324
HOLDING_ACCOUNT_RECIPIENT_IDS: Tuple[int, int, int] = (
    534177364314292244,
    481264459541774356,
    824810834131156992,
)
HOLDING_ACCOUNT_SHARE_LABELS: Tuple[str, ...] = ("02", "03", "24", "final")
HOLDING_TEST_MODE = True
LAST_TEST_SHARE_STRINGS: Dict[str, str] | None = None

# Command Tree for slash commands
tree = bot.tree

log_level_name = os.getenv('LOG_LEVEL', 'INFO').upper()
log_level = getattr(logging, log_level_name, logging.INFO)

# Configure basic logging if not already configured
if not logging.getLogger().hasHandlers():
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
else:
    logging.getLogger().setLevel(log_level)

logger.info("DATA_DIR resolved to %s", DATA_DIR.resolve())
for level, message in TRACKING_PATH_LOGS:
    logger.log(level, message)
logger.info(
    "TRACKING_DATA_PATH summary -> path=%s source=%s option=%r env=%r",
    TRACKING_DATA_PATH,
    TRACKING_DATA_PATH_DETAILS.get('source'),
    TRACKING_DATA_PATH_DETAILS.get('option'),
    TRACKING_DATA_PATH_DETAILS.get('env'),
)

# --- Auto-assign Roles for Lillian ----------------------------------------
# These roles will be applied when the tracked user (Lillian) joins
LILLIAN_ROLE_IDS: tuple[int, int, int] = (
    1397097381626908702,
    1395903086454902836,
    1393104348862746675,
)

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
    global TRACKING_DATA_PATH
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
    except IsADirectoryError:
        logger.error("TRACKING_DATA_PATH %s is a directory; resetting to a file path", TRACKING_DATA_PATH)
        default_data = {
            "tracked_user_id": None,
            "current_session": None,
            "leaderboard": []
        }
        directory_path = TRACKING_DATA_PATH
        new_path = directory_path / 'lillian_tracking.json'
        if new_path == directory_path:
            new_path = DATA_DIR / 'lillian_tracking.json'
        # Update the global path so subsequent calls use the file
        TRACKING_DATA_PATH = new_path
        TRACKING_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Updated TRACKING_DATA_PATH to %s after directory fallback", TRACKING_DATA_PATH.resolve())
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


# --- Web Allowed Users Store -----------------------------------------------
WEB_ALLOWED_USERS: Dict[str, List[str]] = {}
DEFAULT_THEME_SETTINGS = {
    "background_color": "#05070f",
    "background_image": "",
    "accent_color": "#60a5fa",
    "accent_secondary_color": "#a855f7",
    "accent_warning_color": "#f97316",
    "accent_danger_color": "#f87171",
    "text_color": "#f1f5f9",
    "panel_surface_color": "#0b0f1a",
    "panel_surface_opacity": 0.78,
    "panel_card_color": "#0e1624",
    "panel_card_opacity": 0.6,
    "background_blur": 18,
    "panel_blur": 11,
}
WEB_THEME_SETTINGS: Dict[str, object] = dict(DEFAULT_THEME_SETTINGS)


def _normalize_permission_list(perms: Iterable[str] | None) -> List[str]:
    if not perms:
        return []
    sanitized = []
    for perm in perms:
        if perm is None:
            continue
        text = str(perm).strip()
        if text:
            sanitized.append(text)
    return sorted(set(sanitized))


def _sanitize_allowed_users(data: Dict[str, Iterable[str]] | None) -> Dict[str, List[str]]:
    if not data:
        return {}
    cleaned: Dict[str, List[str]] = {}
    for key, value in data.items():
        perms: Iterable[str] | None
        if isinstance(value, (list, tuple, set)):
            perms = value  # type: ignore[assignment]
        elif isinstance(value, str):
            perms = [part.strip() for part in value.split('|')]
        else:
            continue
        normalized = _normalize_permission_list(perms)
        if normalized:
            cleaned[str(key)] = normalized
    return cleaned


def save_allowed_users_data(data: Dict[str, Iterable[str]]) -> None:
    payload = _sanitize_allowed_users(data)
    try:
        ALLOWED_USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with ALLOWED_USERS_FILE.open('w', encoding='utf-8') as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
    except Exception as exc:
        logger.error("Failed to save web allowed users to %s: %s", ALLOWED_USERS_FILE, exc)


def load_allowed_users_data(defaults: Dict[str, Iterable[str]] | None = None) -> Dict[str, List[str]]:
    global WEB_ALLOWED_USERS
    sanitized_defaults = _sanitize_allowed_users(defaults)
    data: Dict[str, List[str]] = {}
    try:
        with ALLOWED_USERS_FILE.open('r', encoding='utf-8') as handle:
            raw = json.load(handle)
        if isinstance(raw, dict):
            data = _sanitize_allowed_users({str(k): v for k, v in raw.items()})
        else:
            logger.warning("Web allowed users store contained non-dict data; resetting with defaults")
            data = sanitized_defaults
    except FileNotFoundError:
        data = sanitized_defaults
        if sanitized_defaults:
            save_allowed_users_data(sanitized_defaults)
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse %s (%s); resetting with defaults", ALLOWED_USERS_FILE, exc)
        data = sanitized_defaults
        save_allowed_users_data(sanitized_defaults)
    except Exception as exc:
        logger.warning("Error loading web allowed users from %s: %s", ALLOWED_USERS_FILE, exc)
        data = sanitized_defaults
        if sanitized_defaults:
            save_allowed_users_data(sanitized_defaults)

    WEB_ALLOWED_USERS = data
    return data


def get_allowed_users_map() -> Dict[str, List[str]]:
    return dict(WEB_ALLOWED_USERS)


def set_allowed_user_permissions(user_id: str, perms: Iterable[str]) -> List[str]:
    global WEB_ALLOWED_USERS
    uid = str(user_id).strip()
    if not uid:
        raise ValueError("user_id is required")
    normalized = _normalize_permission_list(perms)
    if not normalized:
        WEB_ALLOWED_USERS.pop(uid, None)
    else:
        WEB_ALLOWED_USERS[uid] = normalized
    save_allowed_users_data(WEB_ALLOWED_USERS)
    return WEB_ALLOWED_USERS.get(uid, [])


def delete_allowed_user(user_id: str) -> bool:
    global WEB_ALLOWED_USERS
    uid = str(user_id).strip()
    if not uid:
        return False
    removed = WEB_ALLOWED_USERS.pop(uid, None) is not None
    save_allowed_users_data(WEB_ALLOWED_USERS)
    return removed


def _validate_hex_color(value, fallback: str, field: str) -> str:
    if value is None:
        return fallback
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return fallback
        if text.startswith('#'):
            text = text[1:]
        if re.fullmatch(r'[0-9a-fA-F]{6}', text):
            return '#' + text.lower()
    raise ValueError(f"invalid_{field}")


def _coerce_blur_value(value, fallback: int, field: str) -> int:
    if value is None:
        return fallback
    try:
        num = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"invalid_{field}")
    if num < 0:
        num = 0
    if num > 64:
        num = 64
    return int(round(num))


def _coerce_opacity_value(value, fallback: float, field: str) -> float:
    if value is None:
        return fallback
    try:
        num = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"invalid_{field}")
    if num < 0:
        num = 0.0
    if num > 1:
        num = 1.0
    return float(num)


def _merge_theme_settings(base: Mapping[str, object], update: Mapping[str, object] | None) -> Dict[str, object]:
    result: Dict[str, object] = dict(base)
    if not update:
        return result
    if not isinstance(update, Mapping):
        raise ValueError("invalid_theme_payload")

    for key in update.keys():
        if key not in DEFAULT_THEME_SETTINGS:
            raise ValueError(f"unknown_theme_field:{key}")

    current = dict(result)
    if 'background_color' in update:
        current['background_color'] = _validate_hex_color(update.get('background_color'), str(result['background_color']), 'background_color')
    if 'background_image' in update:
        raw = update.get('background_image')
        if raw is None:
            current['background_image'] = ''
        else:
            text = str(raw).strip()
            if len(text) > 1024:
                raise ValueError("background_image_too_long")
            if '\n' in text or '\r' in text:
                raise ValueError("invalid_background_image")
            current['background_image'] = text
    if 'accent_color' in update:
        current['accent_color'] = _validate_hex_color(update.get('accent_color'), str(result['accent_color']), 'accent_color')
    if 'accent_secondary_color' in update:
        current['accent_secondary_color'] = _validate_hex_color(update.get('accent_secondary_color'), str(result['accent_secondary_color']), 'accent_secondary_color')
    if 'accent_warning_color' in update:
        current['accent_warning_color'] = _validate_hex_color(update.get('accent_warning_color'), str(result['accent_warning_color']), 'accent_warning_color')
    if 'accent_danger_color' in update:
        current['accent_danger_color'] = _validate_hex_color(update.get('accent_danger_color'), str(result['accent_danger_color']), 'accent_danger_color')
    if 'text_color' in update:
        current['text_color'] = _validate_hex_color(update.get('text_color'), str(result['text_color']), 'text_color')
    if 'panel_surface_color' in update:
        current['panel_surface_color'] = _validate_hex_color(update.get('panel_surface_color'), str(result['panel_surface_color']), 'panel_surface_color')
    if 'panel_surface_opacity' in update:
        current['panel_surface_opacity'] = _coerce_opacity_value(update.get('panel_surface_opacity'), float(result['panel_surface_opacity']), 'panel_surface_opacity')
    if 'panel_card_color' in update:
        current['panel_card_color'] = _validate_hex_color(update.get('panel_card_color'), str(result['panel_card_color']), 'panel_card_color')
    if 'panel_card_opacity' in update:
        current['panel_card_opacity'] = _coerce_opacity_value(update.get('panel_card_opacity'), float(result['panel_card_opacity']), 'panel_card_opacity')
    if 'background_blur' in update:
        current['background_blur'] = _coerce_blur_value(update.get('background_blur'), int(result['background_blur']), 'background_blur')
    if 'panel_blur' in update:
        current['panel_blur'] = _coerce_blur_value(update.get('panel_blur'), int(result['panel_blur']), 'panel_blur')

    return current


def save_theme_settings(settings: Mapping[str, object]) -> None:
    try:
        THEME_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with THEME_SETTINGS_FILE.open('w', encoding='utf-8') as handle:
            json.dump(dict(settings), handle, indent=2, sort_keys=True)
    except Exception as exc:
        logger.error("Failed to save theme settings to %s: %s", THEME_SETTINGS_FILE, exc)


def load_theme_settings(overrides: Mapping[str, object] | None = None) -> Dict[str, object]:
    global WEB_THEME_SETTINGS
    base: Dict[str, object] = dict(DEFAULT_THEME_SETTINGS)
    if overrides:
        base = _merge_theme_settings(base, overrides)
    try:
        with THEME_SETTINGS_FILE.open('r', encoding='utf-8') as handle:
            raw = json.load(handle)
        if isinstance(raw, Mapping):
            base = _merge_theme_settings(base, raw)
        else:
            logger.warning("Theme settings file %s did not contain a mapping; resetting to defaults", THEME_SETTINGS_FILE)
            save_theme_settings(base)
    except FileNotFoundError:
        save_theme_settings(base)
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse %s (%s); resetting to defaults", THEME_SETTINGS_FILE, exc)
        save_theme_settings(base)
    except Exception as exc:
        logger.warning("Error loading theme settings from %s: %s", THEME_SETTINGS_FILE, exc)
    WEB_THEME_SETTINGS = base
    return dict(WEB_THEME_SETTINGS)


def get_theme_settings() -> Dict[str, object]:
    return dict(WEB_THEME_SETTINGS)


def update_theme_settings(update: Mapping[str, object]) -> Dict[str, object]:
    global WEB_THEME_SETTINGS
    merged = _merge_theme_settings(WEB_THEME_SETTINGS, update)
    WEB_THEME_SETTINGS = merged
    save_theme_settings(WEB_THEME_SETTINGS)
    return dict(WEB_THEME_SETTINGS)


load_theme_settings()

# --- Holding account secret management ------------------------------------
def _generate_holding_password(length: int = HOLDING_ACCOUNT_PASSWORD_LENGTH) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _format_holding_share(index: int, values: Sequence[int]) -> str:
    # Keep the share numeric-only; pad each value to 5 digits (modulus < 100000)
    label = HOLDING_ACCOUNT_SHARE_LABELS[index - 1] if 0 <= index - 1 < len(HOLDING_ACCOUNT_SHARE_LABELS) else str(index)
    return f"{label}{''.join(f'{int(v):05d}' for v in values)}"


def _split_holding_secret(secret_text: str) -> tuple[List[List[int]], Dict[str, str]]:
    secret_bytes = secret_text.encode('utf-8')
    shares: List[List[int]] = [[] for _ in range(HOLDING_ACCOUNT_SHARE_COUNT)]
    for byte_val in secret_bytes:
        random_parts = [secrets.randbelow(HOLDING_ACCOUNT_MODULUS) for _ in range(HOLDING_ACCOUNT_SHARE_COUNT - 1)]
        final_piece = (byte_val - sum(random_parts)) % HOLDING_ACCOUNT_MODULUS
        random_parts.append(final_piece)
        for idx, value in enumerate(random_parts):
            shares[idx].append(int(value))

    share_strings = {str(idx + 1): _format_holding_share(idx + 1, share) for idx, share in enumerate(shares)}
    return shares, share_strings


def save_holding_secret_payload(payload: Mapping[str, object]) -> None:
    try:
        HOLDING_ACCOUNT_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        with HOLDING_ACCOUNT_SECRET_FILE.open('w', encoding='utf-8') as handle:
            json.dump(payload, handle, indent=2)
    except Exception as exc:
        logger.error("Failed to save holding account secret to %s: %s", HOLDING_ACCOUNT_SECRET_FILE, exc)


def load_holding_secret_payload() -> Optional[Dict[str, object]]:
    try:
        with HOLDING_ACCOUNT_SECRET_FILE.open('r', encoding='utf-8') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except FileNotFoundError:
        return None
    except Exception as exc:
        logger.error("Failed to load holding account secret: %s", exc)
        return None


def holding_secret_exists() -> bool:
    return HOLDING_ACCOUNT_SECRET_FILE.exists()


def create_holding_secret(*, persist: bool = True) -> tuple[str, Dict[str, List[int]], Dict[str, str]]:
    if persist and HOLDING_ACCOUNT_SECRET_FILE.exists():
        raise FileExistsError("holding_secret_exists")
    password = _generate_holding_password()
    shares, share_strings = _split_holding_secret(password)
    payload = {
        "password": password,
        "modulus": HOLDING_ACCOUNT_MODULUS,
        "share_count": HOLDING_ACCOUNT_SHARE_COUNT,
        "shares": {str(idx + 1): share for idx, share in enumerate(shares)},
        "share_strings": share_strings,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if persist:
        save_holding_secret_payload(payload)
    return password, {str(idx + 1): share for idx, share in enumerate(shares)}, share_strings


def assemble_holding_password(shares: Mapping[str, Iterable[int]]) -> str:
    expected_keys = [str(i) for i in range(1, HOLDING_ACCOUNT_SHARE_COUNT + 1)]
    ordered_shares: List[List[int]] = []
    for key in expected_keys:
        if key not in shares:
            raise ValueError(f"missing_share_{key}")
        raw_share = shares[key]
        if not isinstance(raw_share, Iterable):
            raise ValueError(f"invalid_share_{key}")
        ordered_shares.append([int(v) for v in raw_share])

    lengths = {len(part) for part in ordered_shares}
    if len(lengths) != 1:
        raise ValueError("share_length_mismatch")

    byte_count = lengths.pop()
    secret_bytes = bytearray()
    for idx in range(byte_count):
        total = sum(part[idx] for part in ordered_shares) % HOLDING_ACCOUNT_MODULUS
        if total < 0 or total > 255:
            raise ValueError("invalid_reconstructed_value")
        secret_bytes.append(total)
    return secret_bytes.decode('utf-8')


def get_holding_share_for_display() -> Optional[Dict[str, str]]:
    share_value = get_cached_test_share_string(HOLDING_ACCOUNT_SHARE_COUNT)
    if not share_value:
        payload = load_holding_secret_payload()
        if not payload:
            return None
        share_strings = payload.get("share_strings")
        if isinstance(share_strings, Mapping):
            share_value = share_strings.get(str(HOLDING_ACCOUNT_SHARE_COUNT))
        if not share_value and isinstance(payload.get("shares"), Mapping):
            raw_share = payload["shares"].get(str(HOLDING_ACCOUNT_SHARE_COUNT))
            if isinstance(raw_share, Iterable):
                try:
                    share_value = _format_holding_share(HOLDING_ACCOUNT_SHARE_COUNT, list(raw_share))
                except Exception:
                    logger.debug("Failed to format holding share for display", exc_info=True)
    if not share_value:
        return None
    return {
        "value": f"View share #{HOLDING_ACCOUNT_SHARE_COUNT}",
        "url": f"/api/holding/share/{HOLDING_ACCOUNT_SHARE_COUNT}",
    }


def load_holding_shares() -> Optional[Dict[str, List[int]]]:
    payload = load_holding_secret_payload()
    if not payload:
        return None
    raw_shares = payload.get("shares")
    if not isinstance(raw_shares, Mapping):
        return None
    cleaned: Dict[str, List[int]] = {}
    for key, val in raw_shares.items():
        if isinstance(val, Iterable):
            try:
                cleaned[str(key)] = [int(v) for v in val]
            except Exception:
                continue
    return cleaned or None


def get_cached_test_share_string(index: int) -> Optional[str]:
    if LAST_TEST_SHARE_STRINGS is None:
        return None
    return LAST_TEST_SHARE_STRINGS.get(str(index))


def _parse_holding_share_input(raw: str, share_index: int) -> List[int]:
    label = HOLDING_ACCOUNT_SHARE_LABELS[share_index - 1] if 0 < share_index <= len(HOLDING_ACCOUNT_SHARE_LABELS) else str(share_index)
    if raw is None:
        raise ValueError("missing")
    text = re.sub(r'\s+', '', str(raw))
    if not text:
        raise ValueError("empty")
    label_lower = label.lower()
    processed = text
    if label_lower and processed.lower().startswith(label_lower):
        processed = processed[len(label):]
    if not processed:
        raise ValueError("no data after label")
    if not processed.isdigit():
        raise ValueError("contains non-numeric characters")
    if len(processed) % 5 != 0:
        raise ValueError("invalid length")
    values = []
    for i in range(0, len(processed), 5):
        segment = processed[i:i+5]
        try:
            values.append(int(segment))
        except ValueError as exc:
            raise ValueError("invalid numeric segment") from exc
    return values


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

async def send_web_activity_message(message=None, embed=None):
    """Send a message to the dedicated web activity channel.

    If WEB_ACTIVITY_CHANNEL_ID is not configured, this becomes a no-op.
    It intentionally does NOT fall back to the monitoring channel.
    """
    if not WEB_ACTIVITY_CHANNEL_ID:
        # Silently skip if not configured to avoid polluting monitoring
        return
    try:
        channel = bot.get_channel(WEB_ACTIVITY_CHANNEL_ID)
        if channel:
            if embed:
                await channel.send(embed=embed)
            elif message:
                await channel.send(message)
        else:
            logger.warning("Web activity channel %s not found", WEB_ACTIVITY_CHANNEL_ID)
    except Exception as e:
        logger.error("Error sending web activity message: %s", e)


async def _deliver_holding_shares(share_strings: Mapping[str, str]) -> tuple[bool, List[str]]:
    """Send the first three holding shares to the configured recipient IDs."""
    errors: List[str] = []
    for idx, user_id in enumerate(HOLDING_ACCOUNT_RECIPIENT_IDS, start=1):
        share_value = share_strings.get(str(idx))
        if not share_value:
            errors.append(f"missing_share_{idx}")
            continue

        label = HOLDING_ACCOUNT_SHARE_LABELS[idx - 1] if idx - 1 < len(HOLDING_ACCOUNT_SHARE_LABELS) else str(idx)

        try:
            user = bot.get_user(user_id) or await bot.fetch_user(user_id)
        except Exception as exc:
            logger.error("Failed to fetch user %s for holding share #%d: %s", user_id, idx, exc)
            errors.append(f"user_unavailable_{user_id}")
            continue

        if not user:
            errors.append(f"user_unavailable_{user_id}")
            continue

        try:
            channel = user.dm_channel or await user.create_dm()
        except Exception as exc:
            logger.error("Failed to create DM channel for %s: %s", user_id, exc)
            errors.append(f"dm_channel_failed_{user_id}")
            continue

        if HOLDING_TEST_MODE:
            body = (
                f"this is part {label} of the password. if this is found out to be shared, the password will be reset.\n"
                f"{share_value}"
            )
        else:
            body = f"Holding account share #{idx}: {share_value}"

        try:
            async for previous in channel.history(limit=1):
                if previous.author == bot.user:
                    try:
                        await previous.delete()
                        logger.debug("Deleted previous holding share DM to %s", user_id)
                    except Exception as exc:
                        logger.debug("Failed to delete previous DM to %s: %s", user_id, exc)
                break
        except Exception as exc:
            logger.debug("Failed to inspect DM history for %s: %s", user_id, exc)

        try:
            await channel.send(body)
        except Exception as exc:
            logger.error("Failed to DM holding share #%d to %s: %s", idx, user_id, exc)
            errors.append(f"dm_failed_{user_id}")

    return len(errors) == 0, errors

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
        # autodefine from the conmsfant in the begiingni of the code
        if member.guild and member.guild.id == CONTROL_SERVER_ID:
            roles_to_add = []
            for rid in LILLIAN_ROLE_IDS:
                role = member.guild.get_role(int(rid))
                if role is None:
                    logger.warning("lillians role id %s not found in server %s", rid, member.guild.id)
                    continue
                if role not in member.roles:
                    roles_to_add.append(role)
            if roles_to_add:
                try:
                    await member.add_roles(*roles_to_add, reason="assigning roles to lillian")
                    logger.info("Assigned %d roles to %s (%s)", len(roles_to_add), str(member), member.id)
                except discord.Forbidden:
                    logger.error("something went wrong and pilot doesnt have permission %s", member.guild.id)
                except discord.HTTPException as e:
                    logger.error("failed to assign lillian roles in guild %s: %s", member.guild.id, e)
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
    allowed_users_defaults: Dict[str, List[str]] = {}
    raw_allowed = options.get('web_allowed_users')
    # Support multiple formats: dict mapping, list of {id, perms}, or CSV string "id:perm|perm,id2:view"
    try:
        if isinstance(raw_allowed, dict):
            for k, v in raw_allowed.items():
                if isinstance(v, (list, tuple, set)):
                    allowed_users_defaults[str(k)] = [p.strip() for p in v if str(p).strip()]
        elif isinstance(raw_allowed, list):
            for item in raw_allowed:
                if isinstance(item, dict) and 'id' in item and 'perms' in item:
                    perms = item['perms'] if isinstance(item['perms'], list) else str(item['perms']).split('|')
                    allowed_users_defaults[str(item['id'])] = [p.strip() for p in perms if p.strip()]
        elif isinstance(raw_allowed, str):
            # id:perm|perm,id2:view
            for part in raw_allowed.split(','):
                part = part.strip()
                if not part or ':' not in part:
                    continue
                uid, perms = part.split(':', 1)
                allowed_users_defaults[str(uid.strip())] = [p.strip() for p in perms.split('|') if p.strip()]
    except Exception as e:
        logger.warning("Failed to parse web_allowed_users: %s", e)

    allowed_users = load_allowed_users_data(allowed_users_defaults)
    logger.info("Loaded %d web allowed user entries", len(allowed_users))

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
@tree.command(name='ping', description='show bot latency', guild=CONTROL_GUILD)
async def ping_slash(interaction: discord.Interaction):
    ms = int(round(bot.latency * 1000))
    await interaction.response.send_message(f"ping: {ms}ms")


@tree.command(name='createholding', description='generate holding account password + shares', guild=CONTROL_GUILD)
@is_owner_and_in_control_channel()
async def create_holding_command(interaction: discord.Interaction):
    global LAST_TEST_SHARE_STRINGS
    if not HOLDING_TEST_MODE and holding_secret_exists():
        await interaction.response.send_message("holding password already exists", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)
    try:
        persist = not HOLDING_TEST_MODE
        password, shares, share_strings = create_holding_secret(persist=persist)
        if persist:
            LAST_TEST_SHARE_STRINGS = None
        else:
            LAST_TEST_SHARE_STRINGS = dict(share_strings)
        if not persist:
            logger.info("Holding account test mode active; generated transient secret without persisting.")
            logger.info("Holding test password: %s", password)
            for idx in range(1, HOLDING_ACCOUNT_SHARE_COUNT + 1):
                share_text = share_strings.get(str(idx))
                raw_share = shares.get(str(idx))
                logger.info("Holding test share %s: %s | raw=%s", idx, share_text, raw_share)
    except FileExistsError:
        await interaction.followup.send("holding password already exists", ephemeral=True)
        return
    except Exception as exc:
        logger.exception("Failed to generate holding account secret: %s", exc)
        await interaction.followup.send("failed to create holding password", ephemeral=True)
        return

    success, errors = await _deliver_holding_shares(share_strings)
    if success:
        await interaction.followup.send("done", ephemeral=False)
    else:
        await interaction.followup.send(
            "holding password saved but failed to DM some shares: " + ", ".join(errors),
            ephemeral=True,
        )


@tree.command(name='assembleholding', description='assemble holding account password from shares', guild=CONTROL_GUILD)
async def assemble_holding_command(
    interaction: discord.Interaction,
    part_one: str,
    part_two: str,
    part_three: str,
    part_four: str,
):
    share_inputs = [part_one, part_two, part_three, part_four]
    share_map: Dict[str, List[int]] = {}
    for idx, raw in enumerate(share_inputs, start=1):
        try:
            share_map[str(idx)] = _parse_holding_share_input(raw, idx)
        except ValueError as exc:
            await interaction.response.send_message(f"invalid share #{idx}: {exc}", ephemeral=True)
            return
    try:
        password = assemble_holding_password(share_map)
    except Exception as exc:
        logger.exception("Failed to assemble holding password from inputs: %s", exc)
        await interaction.response.send_message("failed to assemble holding password", ephemeral=True)
        return
    await interaction.response.send_message(password, ephemeral=True)


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
        ephemeral=False,
    )

# --- Updated Error Handler ---
@tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, NotOwnerError):
        # Custom message for non-owners
        try:
            await interaction.response.send_message('ew who are you you cant tell me what to do', ephemeral=False)
        except discord.InteractionResponded:
            await interaction.followup.send('ew who are you you cant tell me what to do', ephemeral=False)
        return
    elif isinstance(error, WrongChannelError):
        # Custom message for using the command in the wrong channel
        try:
            await interaction.response.send_message('this command cant be used here', ephemeral=True)
        except discord.InteractionResponded:
            await interaction.followup.send('this command cant be used here', ephemeral=True)
        return
    elif isinstance(error, app_commands.CheckFailure):
        # Fallback for any other permission-related errors
        try:
            await interaction.response.send_message('ew who are you you cant tell me what to do', ephemeral=True)
        except discord.InteractionResponded:
            await interaction.followup.send('ew who are you you cant tell me what to do', ephemeral=True)
        return
    else:
        # Log the actual error before notifying the user
        logger.exception("Application command error: %s", error)
        # Try to respond, but catch if already responded
        try:
            if not interaction.response.is_done():
                await interaction.response.send_message('an error occurred', ephemeral=True)
            else:
                await interaction.followup.send('an error occurred', ephemeral=True)
        except Exception as exc:
            logger.error("Failed to send error message: %s", exc)
        return

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
