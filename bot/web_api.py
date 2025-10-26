import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import ssl
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from aiohttp import web
import aiohttp

logger = logging.getLogger(__name__)

# Default fallback port for the embedded web server
DEFAULT_WEB_PORT = 8447


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _mask_secret(value: Optional[str], *, head: int = 4, tail: int = 2) -> str:
    """Return value with most characters masked to avoid leaking secrets."""
    if not value:
        return "<unset>"
    text = str(value)
    if len(text) <= head + tail:
        if len(text) <= 2:
            return "*" * len(text)
        return f"{text[0]}***{text[-1]}"
    return f"{text[:head]}...{text[-tail:]}"


class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)
    
    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed and record it."""
        now = time.time()
        cutoff = now - self.window_seconds
        
        # Clean old requests
        self.requests[key] = [ts for ts in self.requests[key] if ts > cutoff]
        
        # Check limit
        if len(self.requests[key]) >= self.max_requests:
            return False
        
        # Record request
        self.requests[key].append(now)
        return True


class WebAPIServer:
    def __init__(
        self,
        bot,
        *,
        auth_token: str = "",
        oauth_client_id: Optional[str] = None,
        oauth_client_secret: Optional[str] = None,
        oauth_redirect_uri: Optional[str] = None,
        session_secret: Optional[str] = None,
        allowed_users: Optional[Dict[str, Iterable[str]]] = None,
        use_https: bool = False,
    ) -> None:
        self.bot = bot
        self.auth_token = auth_token or ""
        self.oauth_client_id = oauth_client_id
        self.oauth_client_secret = oauth_client_secret
        self.oauth_redirect_uri = oauth_redirect_uri
        
        # Initialize session secret with security checks
        secret_str = session_secret or os.getenv("WEB_SESSION_SECRET") or ""
        if not secret_str:
            # Generate a random secret if none provided (for development)
            logger.warning(
                "No WEB_SESSION_SECRET configured! Generating random secret. "
                "Sessions will not persist across restarts. Set WEB_SESSION_SECRET for production."
            )
            secret_str = secrets.token_urlsafe(32)
        elif len(secret_str) < 16:
            logger.error(
                "WEB_SESSION_SECRET is too short (minimum 16 characters). "
                "Current length: %d. Using it anyway but this is INSECURE.",
                len(secret_str)
            )
        
        self.session_secret = secret_str.encode("utf-8")
        self.use_https = use_https
        
        self.allowed: Dict[str, Set[str]] = {
            str(k): set(v) for k, v in (allowed_users or {}).items()
        }
        self.known_permissions: List[str] = [
            "admin",
            "view",
            "set_status",
            "set_online_status",
            "clear_status",
            "send_message",
            "update_bio",
            "sync_view",
            "sync_manage",
            "tracking_view",
            "tracking_manage",
            "pilot_view",
            "pilot_manage",
            "pilot_chat",
        ]
        
        # Rate limiters
        self.rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
        self.auth_rate_limiter = RateLimiter(max_requests=10, window_seconds=300)  # 10 per 5 min
        self.pilot_rate_limiter = RateLimiter(max_requests=20, window_seconds=60)
        
        # OAuth state tracking (in-memory, expires after 10 minutes)
        self.oauth_states: Dict[str, float] = {}
        
        self._main_module = None
        base_path = Path(__file__).resolve().parent
        default_ui = base_path / 'webui' / 'dist'
        if not default_ui.exists():
            alt_ui = base_path.parent / 'webui' / 'dist'
            if alt_ui.exists():
                default_ui = alt_ui
        self.ui_root = Path(os.getenv('WEB_UI_DIST') or default_ui)
        self.ui_index = self.ui_root / 'index.html'
        logger.info(
            "Web UI static root set to %s (index exists=%s)",
            self.ui_root,
            self.ui_index.is_file(),
        )

        self.app = web.Application(
            middlewares=[self._rate_limit_middleware, self._session_middleware, self._security_headers_middleware],
            client_max_size=2*1024*1024  # 2MB limit
        )
        self._setup_routes()
        self._refresh_allowed_users()

    async def _log_to_discord(self, message: str) -> None:
        """Send a simple monitoring message to the bot's monitoring channel.

        Uses bot.main.send_monitoring_message if available. Best-effort only.
        """
        try:
            main_module = self._main()
            send_fn = getattr(main_module, "send_monitoring_message", None)
            if send_fn and callable(send_fn):
                await send_fn(message=message)
        except Exception as e:
            logger.debug("Failed to send monitoring message: %s", e)

    # ------------------ Session & Auth helpers ------------------
    def _sign(self, payload: Dict) -> str:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        sig = hmac.new(self.session_secret, data, hashlib.sha256).digest()
        return f"{_b64encode(data)}.{_b64encode(sig)}"

    def _verify(self, token: str) -> Optional[Dict]:
        try:
            bdata, bsig = token.split(".", 1)
            data = _b64decode(bdata)
            sig = _b64decode(bsig)
            good = hmac.new(self.session_secret, data, hashlib.sha256).digest()
            if not hmac.compare_digest(sig, good):
                return None
            obj = json.loads(data.decode("utf-8"))
            if obj.get("exp") and int(obj["exp"]) < int(time.time()):
                return None
            return obj
        except Exception as e:
            logger.debug("Session verification failed: %s", e)
            return None

    def _current_user(self, request: web.Request) -> Optional[Tuple[str, str]]:
        tok = request.cookies.get("session")
        if not tok or not self.session_secret:
            return None
        obj = self._verify(tok)
        if not obj:
            return None
        return str(obj.get("id")), obj.get("name")

    def _has_perm(self, user_id: str, perm: str) -> bool:
        perms = self.allowed.get(str(user_id))
        has_perm = bool(perms) and (perm in perms or "admin" in perms)
        if has_perm and "admin" in perms and perm != "admin":
            logger.info("User %s accessed %s via admin permission", user_id, perm)
        return has_perm

    def _get_client_ip(self, request: web.Request) -> str:
        """Get client IP, respecting X-Forwarded-For if behind proxy."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote or "unknown"

    def _generate_csrf_token(self, user_id: str) -> str:
        """Generate a CSRF token for a user session."""
        payload = {
            "user_id": user_id,
            "exp": int(time.time()) + 3600,  # 1 hour expiry
            "nonce": secrets.token_urlsafe(16)
        }
        return self._sign(payload)

    def _verify_csrf_token(self, token: str, user_id: str) -> bool:
        """Verify a CSRF token matches the current user."""
        if not token:
            return False
        obj = self._verify(token)
        if not obj:
            return False
        return obj.get("user_id") == user_id

    @web.middleware
    async def _rate_limit_middleware(self, request: web.Request, handler):
        """Apply rate limiting to all requests."""
        client_ip = self._get_client_ip(request)
        
        # Stricter rate limit for auth endpoints
        if request.path in ["/oauth/callback", "/login"]:
            if not self.auth_rate_limiter.is_allowed(client_ip):
                logger.warning("Rate limit exceeded for auth endpoint from %s", client_ip)
                return web.json_response(
                    {"error": "rate_limit_exceeded", "message": "Too many authentication attempts"},
                    status=429
                )
        # Stricter rate limit for pilot chat
        elif request.path == "/api/pilot/chat":
            if not self.pilot_rate_limiter.is_allowed(client_ip):
                logger.warning("Rate limit exceeded for pilot chat from %s", client_ip)
                return web.json_response(
                    {"error": "rate_limit_exceeded", "message": "Too many chat requests"},
                    status=429
                )
        # General rate limit for API endpoints
        elif request.path.startswith("/api/"):
            if not self.rate_limiter.is_allowed(client_ip):
                logger.warning("Rate limit exceeded from %s", client_ip)
                return web.json_response(
                    {"error": "rate_limit_exceeded", "message": "Too many requests"},
                    status=429
                )
        
        return await handler(request)

    @web.middleware
    async def _session_middleware(self, request: web.Request, handler):
        request["user"] = self._current_user(request)
        return await handler(request)

    @web.middleware
    async def _security_headers_middleware(self, request: web.Request, handler):
        """Add security headers to all responses."""
        response = await handler(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Content Security Policy
        if request.path == "/" or request.path.startswith("/assets"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "connect-src 'self'; "
                "font-src 'self' data:; "
                "frame-ancestors 'none'"
            )
        
        return response

    async def _verify_csrf(self, request: web.Request) -> bool:
        """Verify CSRF token for state-changing operations."""
        user = request.get("user")
        if not user:
            return False
        
        uid, _ = user
        
        # Check for CSRF token in header or form data
        csrf_token = request.headers.get("X-CSRF-Token")
        if not csrf_token:
            # Try to get from request body
            try:
                if request.content_type == "application/json":
                    body = await request.json()
                    csrf_token = body.get("csrf_token")
                else:
                    form = await request.post()
                    csrf_token = form.get("csrf_token")
            except Exception:
                pass
        
        if not csrf_token:
            logger.warning("CSRF token missing for %s from user %s", request.path, uid)
            return False
        
        if not self._verify_csrf_token(csrf_token, uid):
            logger.warning("CSRF token invalid for %s from user %s", request.path, uid)
            return False
        
        return True

    # ------------------ Routing ------------------
    def _setup_routes(self) -> None:
        # Public
        self.app.router.add_get("/health", self.handle_health)

        # OAuth
        self.app.router.add_get("/login", self.handle_login)
        self.app.router.add_get("/oauth/callback", self.handle_oauth_callback)
        self.app.router.add_get("/logout", self.handle_logout)

        # API (auth required)
        self.app.router.add_get("/api/session", self.handle_session)
        self.app.router.add_get("/api/csrf", self.handle_csrf_token)
        self.app.router.add_get("/api/status", self.handle_status)
        self.app.router.add_post("/api/message", self.handle_send_message)
        self.app.router.add_post("/api/set_status", self.handle_set_status)
        self.app.router.add_post("/api/set_online", self.handle_set_online_status)
        self.app.router.add_post("/api/clear_status", self.handle_clear_status)
        self.app.router.add_post("/api/update_bio", self.handle_update_bio)
        self.app.router.add_post("/api/sync/enable", self.handle_sync_enable)
        self.app.router.add_post("/api/sync/disable", self.handle_sync_disable)
        self.app.router.add_get("/api/sync/status", self.handle_sync_status)
        self.app.router.add_post("/api/tracking/set_user", self.handle_tracking_set_user)
        self.app.router.add_get("/api/tracking/status", self.handle_tracking_status)
        self.app.router.add_get("/api/tracking/leaderboard", self.handle_tracking_leaderboard)
        self.app.router.add_post("/api/tracking/clear", self.handle_tracking_clear)
        self.app.router.add_get("/api/pilot/state", self.handle_pilot_state)
        self.app.router.add_post("/api/pilot/mode", self.handle_pilot_mode)
        self.app.router.add_post("/api/pilot/style", self.handle_pilot_style)
        self.app.router.add_post("/api/pilot/chat", self.handle_pilot_chat)

        # Admin
        self.app.router.add_get("/api/admin/permissions", self.handle_admin_permissions_list)
        self.app.router.add_post("/api/admin/permissions", self.handle_admin_permissions_upsert)
        self.app.router.add_delete("/api/admin/permissions/{user_id}", self.handle_admin_permissions_delete)

        if self.ui_root.is_dir():
            assets_dir = self.ui_root / 'assets'
            if assets_dir.is_dir():
                logger.info("Serving static assets from %s", assets_dir)
                self.app.router.add_static('/assets', str(assets_dir), show_index=False)
            else:
                logger.warning("Assets directory missing at %s; UI may not load correctly", assets_dir)
        else:
            logger.warning("Web UI root %s does not exist; serving fallback HTML", self.ui_root)

        self.app.router.add_get('/{tail:.*}', self.handle_index)

    def _main(self):
        if self._main_module is None:
            import sys
            # Prefer the already-loaded entry point module to avoid re-importing main.py.
            for candidate in ("bot.main", "main", "__main__"):
                mod = sys.modules.get(candidate)
                if mod and getattr(mod, "__file__", "").endswith(("bot/main.py", "bot\\main.py")):
                    self._main_module = mod
                    break
            if self._main_module is None:
                # Fallback to importing via the package, covering python -m bot.main invocations.
                try:
                    from . import main as main_module  # type: ignore cyclical import only at runtime
                except ImportError:
                    import importlib
                    main_module = importlib.import_module("bot.main")
                self._main_module = main_module
        return self._main_module

    def _refresh_allowed_users(self) -> None:
        main_module = self._main()
        store = getattr(main_module, "WEB_ALLOWED_USERS", None)
        if not isinstance(store, dict):
            return
        refreshed: Dict[str, Set[str]] = {}
        for uid, perms in store.items():
            if isinstance(perms, (list, tuple, set)):
                normalized = {str(p).strip() for p in perms if str(p).strip()}
            else:
                continue
            refreshed[str(uid)] = normalized
        self.allowed = refreshed

    async def _payload(self, request: web.Request) -> Dict:
        if request.content_type == "application/json":
            try:
                data = await request.json()
                if isinstance(data, dict):
                    return data
            except Exception as e:
                logger.debug("Failed to parse JSON payload: %s", e)
                return {}
        form = await request.post()
        return {k: form[k] for k in form}

    # ------------------ Handlers ------------------
    async def handle_health(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def handle_index(self, request: web.Request) -> web.StreamResponse:
        if getattr(self, "ui_index", None) and self.ui_index.is_file():
            return web.FileResponse(path=self.ui_index)

        fallback = (
            "<html><body style='font-family: sans-serif; padding: 3rem; background: #05070f; color: #f1f5f9'>"
            "<h2>Pilot Control Deck</h2>"
            "<p>The compiled web UI is not available. Run <code>npm install</code> and <code>npm run build</code> inside <strong>webui/</strong>.</p>"
            "<p><a href='/login' style='color:#60a5fa'>Login with Discord</a></p>"
            "</body></html>"
        )
        return web.Response(text=fallback, content_type="text/html")

    async def handle_login(self, request: web.Request) -> web.Response:
        if not (self.oauth_client_id and self.oauth_redirect_uri):
            return web.Response(status=503, text="OAuth not configured")
        
        # Generate and store OAuth state for CSRF protection
        state = secrets.token_urlsafe(32)
        self.oauth_states[state] = time.time()
        
        # Clean up old states (older than 10 minutes)
        cutoff = time.time() - 600
        self.oauth_states = {k: v for k, v in self.oauth_states.items() if v > cutoff}
        
        params = {
            "client_id": self.oauth_client_id,
            "redirect_uri": self.oauth_redirect_uri,
            "response_type": "code",
            "scope": "identify",
            "prompt": "consent",
            "state": state,
        }
        from urllib.parse import urlencode

        url = f"https://discord.com/api/oauth2/authorize?{urlencode(params)}"
        raise web.HTTPFound(url)

    async def handle_oauth_callback(self, request: web.Request) -> web.Response:
        if not (self.oauth_client_id and self.oauth_client_secret and self.oauth_redirect_uri and self.session_secret):
            return web.Response(status=503, text="OAuth not configured")
        
        code = request.query.get("code")
        state = request.query.get("state")
        
        if not code:
            return web.Response(status=400, text="Missing code")
        
        # Verify OAuth state to prevent CSRF
        if not state or state not in self.oauth_states:
            logger.warning("Invalid OAuth state from %s", self._get_client_ip(request))
            return web.Response(status=400, text="Invalid state parameter")
        
        # Remove used state
        del self.oauth_states[state]

        token_data = {
            "client_id": self.oauth_client_id,
            "client_secret": self.oauth_client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.oauth_redirect_uri,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post("https://discord.com/api/oauth2/token", data=token_data, headers=headers) as resp:
                    if resp.status != 200:
                        logger.error("OAuth token exchange failed: %s", resp.status)
                        return web.Response(status=500, text="Authentication failed")
                    tok = await resp.json()
                    access_token = tok.get("access_token")
                    if not access_token:
                        return web.Response(status=500, text="Authentication failed")

                user_headers = {"Authorization": f"Bearer {access_token}"}
                async with session.get("https://discord.com/api/users/@me", headers=user_headers) as r2:
                    if r2.status != 200:
                        logger.error("OAuth user fetch failed: %s", r2.status)
                        return web.Response(status=500, text="Authentication failed")
                    user = await r2.json()
        except Exception as e:
            logger.exception("OAuth flow error")
            return web.Response(status=500, text="Authentication failed")

        uid = str(user.get("id"))
        name = user.get("global_name") or user.get("username") or uid
        payload = {"id": uid, "name": name, "exp": int(time.time()) + 3600 * 12}
        cookie = self._sign(payload)
        resp = web.HTTPFound("/")
        resp.set_cookie(
            "session",
            cookie,
            httponly=True,
            secure=self.use_https,
            samesite="Lax",
            max_age=3600 * 12
        )
        logger.info("User %s (%s) logged in successfully", name, uid)
        return resp

    async def handle_logout(self, request: web.Request) -> web.Response:
        resp = web.HTTPFound("/")
        resp.del_cookie("session")
        return resp

    async def handle_session(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"authenticated": False})

        uid, name = user
        perms = sorted(self.allowed.get(str(uid), set()))
        return web.json_response({
            "authenticated": True,
            "user": {"id": uid, "name": name},
            "permissions": perms,
        })

    async def handle_csrf_token(self, request: web.Request) -> web.Response:
        """Generate a CSRF token for the current user."""
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        
        uid, _ = user
        csrf_token = self._generate_csrf_token(uid)
        return web.json_response({"csrf_token": csrf_token})

    async def handle_status(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "view"):
            return web.json_response({"error": "forbidden"}, status=403)

        me = getattr(self.bot, "user", None)
        presence_status = None
        presence_activity = None
        for guild in getattr(self.bot, "guilds", []) or []:
            me_member = getattr(guild, "me", None)
            if me_member:
                presence_status = getattr(me_member.status, "name", None)
                activity = getattr(me_member, "activity", None)
                if activity:
                    presence_activity = {
                        "type": getattr(getattr(activity, "type", None), "name", None),
                        "name": getattr(activity, "name", None),
                    }
                break

        main_module = self._main()
        original_activity = getattr(main_module, "bot_original_activity", None)
        if original_activity:
            original_activity_payload = {
                "type": getattr(getattr(original_activity, "type", None), "name", None),
                "name": getattr(original_activity, "name", None),
            }
        else:
            original_activity_payload = None

        data = {
            "bot": {
                "id": getattr(me, "id", None),
                "name": getattr(me, "name", None),
            },
            "guild_count": len(getattr(self.bot, "guilds", []) or []),
            "latency": getattr(self.bot, "latency", None),
            "presence": {
                "status": presence_status,
                "activity": presence_activity,
            },
            "sync": {
                "enabled": getattr(main_module, "owner_status_sync_enabled", False),
                "stored_activity": original_activity_payload,
                "manually_set_offline": getattr(main_module, "bot_was_manually_set_offline", False),
            },
        }
        return web.json_response(data)

    async def handle_send_message(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "send_message"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        payload = await self._payload(request)
        channel_id = payload.get("channel_id")
        content = payload.get("content")

        if not channel_id or not content:
            return web.json_response({"error": "channel_id_and_content_required"}, status=400)

        # Validate content length (Discord limit)
        content_str = str(content)
        if len(content_str) > 2000:
            return web.json_response({"error": "message_too_long", "max_length": 2000}, status=400)

        try:
            channel_id_int = int(str(channel_id))
        except Exception:
            return web.json_response({"error": "invalid_channel_id"}, status=400)

        channel = self.bot.get_channel(channel_id_int)
        if channel is None:
            try:
                channel = await self.bot.fetch_channel(channel_id_int)
            except Exception as e:
                logger.debug("Failed to fetch channel %s: %s", channel_id_int, e)
                channel = None

        if channel is None:
            return web.json_response({"error": "channel_not_found"}, status=404)

        try:
            await channel.send(content_str)
            logger.info("User %s sent message to channel %s", uid, channel_id_int)
            # Log to monitoring channel
            preview = (content_str[:180] + "…") if len(content_str) > 180 else content_str
            await self._log_to_discord(f"webui: <@{uid}> sent message to <#{channel_id_int}>: {preview}")
            return web.json_response({"ok": True})
        except Exception as e:
            logger.exception("Failed to send message via web API")
            return web.json_response({"error": "send_failed"}, status=500)

    async def handle_set_status(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "set_status"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        payload = await self._payload(request)
        status_type = (payload.get("type") or "").lower()
        status_text = payload.get("text") or ""

        if not status_text:
            return web.json_response({"error": "text_required"}, status=400)

        # Validate status text length (Discord limit is 128)
        if len(status_text) > 128:
            return web.json_response({"error": "status_too_long", "max_length": 128}, status=400)

        import discord  # local import to avoid hard dependency if unused

        status_map = {
            'playing': discord.ActivityType.playing,
            'watching': discord.ActivityType.watching,
            'listening': discord.ActivityType.listening,
            'streaming': discord.ActivityType.streaming,
            'competing': discord.ActivityType.competing,
        }
        if status_type not in status_map:
            return web.json_response({"error": "invalid_type"}, status=400)

        activity = discord.Activity(type=status_map[status_type], name=status_text)
        try:
            await self.bot.change_presence(status=discord.Status.online, activity=activity)
            main_module = self._main()
            setattr(main_module, "bot_original_activity", activity)
            setattr(main_module, "bot_was_manually_set_offline", False)
            logger.info("User %s set bot status to %s: %s", uid, status_type, status_text)
            # Log equivalent command to monitoring channel
            await self._log_to_discord(f"/setstatus {status_type} {status_text} (via web by <@{uid}>)")
            return web.json_response({"ok": True})
        except Exception as e:
            logger.exception("Failed to set status via web API")
            return web.json_response({"error": "status_change_failed"}, status=500)

    async def handle_set_online_status(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "set_online_status"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        payload = await self._payload(request)
        status_value = (payload.get("status") or payload.get("online_status") or "").lower()

        import discord

        status_map = {
            'online': discord.Status.online,
            'idle': discord.Status.idle,
            'dnd': discord.Status.dnd,
            'invisible': discord.Status.invisible,
        }
        if status_value not in status_map:
            return web.json_response({"error": "invalid_status"}, status=400)

        current_activity = None
        for guild in getattr(self.bot, "guilds", []) or []:
            me_member = getattr(guild, "me", None)
            if me_member and getattr(me_member, "activity", None):
                current_activity = me_member.activity
                break

        try:
            await self.bot.change_presence(status=status_map[status_value], activity=current_activity)
            main_module = self._main()
            setattr(main_module, "bot_was_manually_set_offline", status_value == 'invisible')
            logger.info("User %s set bot online status to %s", uid, status_value)
            # Log equivalent command to monitoring channel
            await self._log_to_discord(f"/setonline {status_value} (via web by <@{uid}>)")
            return web.json_response({"ok": True})
        except Exception as e:
            logger.exception("Failed to set online status via web API")
            return web.json_response({"error": "status_change_failed"}, status=500)

    async def handle_clear_status(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "clear_status"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        import discord

        try:
            await self.bot.change_presence(status=discord.Status.online, activity=None)
            main_module = self._main()
            setattr(main_module, "bot_original_activity", None)
            setattr(main_module, "bot_was_manually_set_offline", False)
            logger.info("User %s cleared bot status", uid)
            # Log equivalent command to monitoring channel
            await self._log_to_discord(f"/clearstatus (via web by <@{uid}>)")
            return web.json_response({"ok": True})
        except Exception as e:
            logger.exception("Failed to clear status via web API")
            return web.json_response({"error": "status_clear_failed"}, status=500)

    async def handle_sync_enable(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "sync_manage"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        main_module = self._main()
        setattr(main_module, "owner_status_sync_enabled", True)
        logger.info("User %s enabled status sync", uid)
        await self._log_to_discord(f"/syncme (via web by <@{uid}>)")
        return web.json_response({"ok": True, "enabled": True})

    async def handle_sync_disable(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "sync_manage"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        main_module = self._main()
        setattr(main_module, "owner_status_sync_enabled", False)
        logger.info("User %s disabled status sync", uid)
        await self._log_to_discord(f"/nosync (via web by <@{uid}>)")
        return web.json_response({"ok": True, "enabled": False})

    async def handle_sync_status(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not (self._has_perm(uid, "sync_view") or self._has_perm(uid, "sync_manage")):
            return web.json_response({"error": "forbidden"}, status=403)

        main_module = self._main()
        sync_enabled = getattr(main_module, "owner_status_sync_enabled", False)
        original_activity = getattr(main_module, "bot_original_activity", None)
        if original_activity:
            stored = {
                "type": getattr(getattr(original_activity, "type", None), "name", None),
                "name": getattr(original_activity, "name", None),
            }
        else:
            stored = None

        guild = self.bot.get_guild(getattr(main_module, "CONTROL_SERVER_ID", 0))
        owner_status = None
        if guild and self.bot.owner_id:
            owner = guild.get_member(self.bot.owner_id)
            if owner and getattr(owner, "status", None):
                owner_status = owner.status.name

        return web.json_response({
            "enabled": sync_enabled,
            "stored_activity": stored,
            "owner_status": owner_status,
            "manually_set_offline": getattr(main_module, "bot_was_manually_set_offline", False),
        })

    async def handle_tracking_set_user(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "tracking_manage"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        payload = await self._payload(request)
        raw_user_id = payload.get("user_id")
        try:
            user_id_int = int(str(raw_user_id))
        except Exception:
            return web.json_response({"error": "invalid_user_id"}, status=400)

        main_module = self._main()
        tracking_data = main_module.load_tracking_data()
        tracking_data["tracked_user_id"] = user_id_int
        main_module.save_tracking_data(tracking_data)
        logger.info("User %s set tracked user to %s", uid, user_id_int)
        await self._log_to_discord(f"/settrackuser {user_id_int} (via web by <@{uid}>)")
        return web.json_response({"ok": True, "tracked_user_id": user_id_int})

    async def handle_tracking_status(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not (self._has_perm(uid, "tracking_view") or self._has_perm(uid, "tracking_manage")):
            return web.json_response({"error": "forbidden"}, status=403)

        main_module = self._main()
        tracking_data = main_module.load_tracking_data()
        tracked_user_id = tracking_data.get("tracked_user_id")
        if not tracked_user_id:
            return web.json_response({"tracked_user_id": None, "in_server": False})

        guild = self.bot.get_guild(getattr(main_module, "CONTROL_SERVER_ID", 0))
        member = guild.get_member(tracked_user_id) if guild else None
        in_server = member is not None

        current_session = tracking_data.get("current_session") or {}
        session_payload = None
        if current_session:
            join_time_str = current_session.get("join_time")
            if join_time_str:
                try:
                    join_time = datetime.fromisoformat(join_time_str.replace('Z', '+00:00'))
                    duration = datetime.now(timezone.utc) - join_time
                    days = duration.days
                    hours = duration.seconds // 3600
                    minutes = (duration.seconds % 3600) // 60
                    if days > 0:
                        duration_text = f"{days} days, {hours} hours, {minutes} minutes"
                    elif hours > 0:
                        duration_text = f"{hours} hours, {minutes} minutes"
                    else:
                        duration_text = f"{minutes} minutes"
                    session_payload = {
                        "join_time": join_time_str,
                        "duration": {
                            "days": days,
                            "hours": hours,
                            "minutes": minutes,
                        },
                        "duration_text": duration_text,
                    }
                except Exception as e:
                    logger.debug("Failed to parse session time: %s", e)
                    session_payload = {"join_time": join_time_str}

        return web.json_response({
            "tracked_user_id": tracked_user_id,
            "in_server": in_server,
            "current_session": session_payload,
        })

    async def handle_tracking_leaderboard(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not (self._has_perm(uid, "tracking_view") or self._has_perm(uid, "tracking_manage")):
            return web.json_response({"error": "forbidden"}, status=403)

        main_module = self._main()
        tracking_data = main_module.load_tracking_data()
        leaderboard = tracking_data.get("leaderboard", [])
        return web.json_response({"leaderboard": leaderboard[:10], "total": len(leaderboard)})

    async def handle_tracking_clear(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "tracking_manage"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        main_module = self._main()
        tracking_data = {
            "tracked_user_id": None,
            "current_session": None,
            "leaderboard": [],
        }
        main_module.save_tracking_data(tracking_data)
        logger.info("User %s cleared tracking data", uid)
        await self._log_to_discord(f"/cleartracking (via web by <@{uid}>)")
        return web.json_response({"ok": True})

    async def handle_pilot_state(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not (self._has_perm(uid, "pilot_view") or self._has_perm(uid, "pilot_manage") or self._has_perm(uid, "pilot_chat")):
            return web.json_response({"error": "forbidden"}, status=403)

        pilot_cog = self.bot.get_cog("PilotChatCog")
        if not pilot_cog:
            return web.json_response({"enabled": False, "available": False})

        return web.json_response({
            "available": True,
            "enabled": getattr(pilot_cog, "enabled", False),
            "style_mode": getattr(pilot_cog, "style_mode", None),
            "history_limit": getattr(pilot_cog, "history_limit", None),
            "response_channel_id": getattr(pilot_cog, "response_channel_id", None),
        })

    async def handle_pilot_mode(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "pilot_manage"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        pilot_cog = self.bot.get_cog("PilotChatCog")
        if not pilot_cog:
            return web.json_response({"error": "pilot_not_available"}, status=503)

        payload = await self._payload(request)
        state = (payload.get("state") or '').lower()
        if state not in {"on", "off", "enable", "disable", "true", "false"}:
            return web.json_response({"error": "invalid_state"}, status=400)
        enable = state in {"on", "enable", "true"}
        pilot_cog.enabled = enable
        logger.info("User %s %s pilot mode", uid, "enabled" if enable else "disabled")
        await self._log_to_discord(f"webui: <@{uid}> set pilot {'on' if enable else 'off'}")
        return web.json_response({"ok": True, "enabled": enable})

    async def handle_pilot_style(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "pilot_manage"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        pilot_cog = self.bot.get_cog("PilotChatCog")
        if not pilot_cog:
            return web.json_response({"error": "pilot_not_available"}, status=503)

        payload = await self._payload(request)
        mode = (payload.get("mode") or '').lower()
        if not mode:
            return web.json_response({"error": "mode_required"}, status=400)
        
        # Validate mode length to prevent abuse
        if len(mode) > 50:
            return web.json_response({"error": "mode_too_long"}, status=400)
        
        pilot_cog.style_mode = mode
        logger.info("User %s set pilot style mode to %s", uid, mode)
        await self._log_to_discord(f"webui: <@{uid}> set pilot style to {mode}")
        return web.json_response({"ok": True, "style_mode": mode})

    async def handle_pilot_chat(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, name = user
        if not self._has_perm(uid, "pilot_chat"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        pilot_cog = self.bot.get_cog("PilotChatCog")
        if not pilot_cog:
            return web.json_response({"error": "pilot_not_available"}, status=503)

        payload = await self._payload(request)
        message = payload.get("message") or payload.get("content")
        if not message:
            return web.json_response({"error": "message_required"}, status=400)

        # Validate message length
        message_str = str(message)
        if len(message_str) > 2000:
            return web.json_response({"error": "message_too_long", "max_length": 2000}, status=400)

        history = payload.get("history")
        if history and not isinstance(history, list):
            return web.json_response({"error": "history_must_be_list"}, status=400)
        if isinstance(history, list):
            # Limit history size to prevent abuse
            if len(history) > 50:
                return web.json_response({"error": "history_too_long", "max_length": 50}, status=400)
            
            cleaned_history: List[Dict[str, str]] = []
            for item in history:
                if isinstance(item, dict):
                    role = item.get("role")
                    content = item.get("content")
                    if role in {"user", "assistant"} and content:
                        # Limit individual history message length
                        content_str = str(content)
                        if len(content_str) > 2000:
                            content_str = content_str[:2000]
                        cleaned_history.append({"role": str(role), "content": content_str})
            history = cleaned_history

        try:
            reply = await pilot_cog.generate_web_reply(
                username=payload.get("username") or name,
                content=message_str,
                history=history,
            )
        except RuntimeError as e:
            if str(e) == "pilot_chat_disabled":
                return web.json_response({"error": "pilot_disabled"}, status=409)
            logger.exception("Pilot chat error")
            return web.json_response({"error": "chat_failed"}, status=500)
        except Exception as e:
            logger.exception("Failed to run pilot chat via web API")
            return web.json_response({"error": "chat_failed"}, status=500)
        try:
            preview = (message_str[:180] + "…") if len(message_str) > 180 else message_str
            await self._log_to_discord(f"webui: <@{uid}> pilot chat → {preview}")
        except Exception:
            pass
        return web.json_response({"reply": reply})

    async def handle_admin_permissions_list(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "admin"):
            return web.json_response({"error": "forbidden"}, status=403)

        self._refresh_allowed_users()
        users_payload = [
            {"id": user_id, "permissions": sorted(perms)}
            for user_id, perms in sorted(self.allowed.items())
        ]
        available = sorted(set(self.known_permissions) | {perm for perms in self.allowed.values() for perm in perms})
        return web.json_response({
            "users": users_payload,
            "available_permissions": available,
        })

    async def handle_admin_permissions_upsert(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "admin"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        payload = await self._payload(request)
        user_id = str(payload.get("user_id") or payload.get("id") or "").strip()
        if not user_id:
            return web.json_response({"error": "user_id_required"}, status=400)

        raw_perms = payload.get("permissions") or payload.get("perms") or []
        perms_list: List[str] = []
        if isinstance(raw_perms, list):
            source = raw_perms
        elif isinstance(raw_perms, str):
            source = [part.strip() for part in raw_perms.replace('|', ',').split(',')]
        else:
            source = []
        for perm in source:
            text = str(perm).strip()
            if text:
                perms_list.append(text)

        valid_set = []
        known = set(self.known_permissions)
        for perms in self.allowed.values():
            known.update(perms)
        for perm in perms_list:
            if perm in known and perm not in valid_set:
                valid_set.append(perm)

        main_module = self._main()
        if not valid_set:
            main_module.delete_allowed_user(user_id)
            self._refresh_allowed_users()
            logger.info("User %s removed all permissions for %s", uid, user_id)
            await self._log_to_discord(f"webui: <@{uid}> cleared web permissions for <@{user_id}>")
            return web.json_response({"ok": True, "user": {"id": user_id, "permissions": []}})

        try:
            updated = main_module.set_allowed_user_permissions(user_id, valid_set)
        except ValueError:
            return web.json_response({"error": "user_id_required"}, status=400)

        self._refresh_allowed_users()
        logger.info("User %s updated permissions for %s: %s", uid, user_id, valid_set)
        try:
            await self._log_to_discord(
                f"webui: <@{uid}> set web permissions for <@{user_id}> → {', '.join(updated)}"
            )
        except Exception:
            pass
        return web.json_response({"ok": True, "user": {"id": user_id, "permissions": updated}})

    async def handle_admin_permissions_delete(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "admin"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        user_id = request.match_info.get("user_id", "").strip()
        if not user_id:
            return web.json_response({"error": "user_id_required"}, status=400)

        main_module = self._main()
        removed = main_module.delete_allowed_user(user_id)
        self._refresh_allowed_users()
        logger.info("User %s deleted permissions for %s", uid, user_id)
        await self._log_to_discord(f"webui: <@{uid}> deleted web permissions for <@{user_id}>")
        return web.json_response({"ok": True, "removed": removed})

    async def handle_update_bio(self, request: web.Request) -> web.Response:
        user = request.get("user")
        if not user:
            return web.json_response({"error": "unauthorized"}, status=401)
        uid, _ = user
        if not self._has_perm(uid, "update_bio"):
            return web.json_response({"error": "forbidden"}, status=403)

        if not await self._verify_csrf(request):
            return web.json_response({"error": "csrf_validation_failed"}, status=403)

        if request.content_type == "application/json":
            try:
                body = await request.json()
            except Exception:
                return web.json_response({"error": "invalid_json"}, status=400)
            bio_text = body.get("bio") or ""
        else:
            form = await request.post()
            bio_text = form.get("bio") or ""

        if not bio_text:
            return web.json_response({"error": "bio_required"}, status=400)

        # Validate bio length (Discord limit is 190 characters)
        bio_str = str(bio_text)
        if len(bio_str) > 190:
            return web.json_response({"error": "bio_too_long", "max_length": 190}, status=400)

        # Patch Discord user profile using bot token
        url = "https://discord.com/api/v10/users/@me"
        headers = {
            "Authorization": f"Bot {self.bot.http.token}",
            "Content-Type": "application/json",
        }
        data = {"bio": bio_str}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.patch(url, json=data, headers=headers) as response:
                    if response.status != 200:
                        logger.error("Failed to update bio: %s", response.status)
                        return web.json_response({"error": "bio_update_failed"}, status=500)
        except Exception as e:
            logger.exception("Failed to update bio via web API")
            return web.json_response({"error": "bio_update_failed"}, status=500)

        logger.info("User %s updated bot bio", uid)
        bio_preview = (bio_str[:160] + "…") if len(bio_str) > 160 else bio_str
        await self._log_to_discord(f"/updatebio {bio_preview} (via web by <@{uid}>)")
        return web.json_response({"ok": True})


async def start_web_server(
    bot,
    *,
    host: str = "0.0.0.0",
    port: int = DEFAULT_WEB_PORT,
    ssl_context: Optional[ssl.SSLContext] = None,
    auth_token: str = "",
    oauth_client_id: Optional[str] = None,
    oauth_client_secret: Optional[str] = None,
    oauth_redirect_uri: Optional[str] = None,
    session_secret: Optional[str] = None,
    allowed_users: Optional[Dict[str, Iterable[str]]] = None,
) -> None:
    """Start the aiohttp web server without blocking the bot loop.

    Uses AppRunner + TCPSite so it runs within the existing event loop.
    """
    logger.info(
        "Initializing Web API server host=%s port=%s ssl=%s oauth_client=%s allowed_users=%d",
        host,
        port,
        bool(ssl_context),
        oauth_client_id,
        len(allowed_users or {}),
    )

    # Verbose guidance when OAuth is not fully configured
    scheme_hint = "https" if ssl_context else "http"
    effective_session_secret = session_secret or os.getenv("WEB_SESSION_SECRET")
    missing: list[str] = []
    if not oauth_client_id:
        missing.append("WEB_OAUTH_CLIENT_ID")
    if not oauth_client_secret:
        missing.append("WEB_OAUTH_CLIENT_SECRET")
    if not oauth_redirect_uri:
        missing.append("WEB_OAUTH_REDIRECT_URI")
    if not effective_session_secret:
        missing.append("WEB_SESSION_SECRET")

    if missing:
        logger.warning(
            "OAuth not configured; missing %s. The /login route will be disabled.",
            ", ".join(missing),
        )
        logger.info(
            "To enable dashboard login, set the missing env vars and use redirect URI like: %s://<your-host>:%s/oauth/callback",
            scheme_hint,
            port,
        )
    logger.info(
        "OAuth credentials (masked): client_id=%s client_secret=%s redirect_uri=%s session_secret=%s",
        _mask_secret(oauth_client_id),
        _mask_secret(oauth_client_secret),
        oauth_redirect_uri or "<unset>",
        _mask_secret(effective_session_secret),
    )
    if not missing:
        logger.info("OAuth configured! Web login endpoints are enabled.")

    server = WebAPIServer(
        bot,
        auth_token=auth_token,
        oauth_client_id=oauth_client_id,
        oauth_client_secret=oauth_client_secret,
        oauth_redirect_uri=oauth_redirect_uri,
        session_secret=session_secret,
        allowed_users=allowed_users,
        use_https=bool(ssl_context),
    )
    runner = web.AppRunner(server.app)
    await runner.setup()

    site = web.TCPSite(runner, host=host, port=int(port), ssl_context=ssl_context)
    try:
        await site.start()
    except Exception:
        logger.exception("Failed to start Web API server on %s:%s", host, port)
        raise

    scheme = "https" if ssl_context else "http"
    logger.info("Web API server started on %s://%s:%s", scheme, host, port)

    # Keep a reference on the bot for potential future shutdown
    setattr(bot, "_web_api_runner", runner)
    setattr(bot, "_web_api_site", site)
