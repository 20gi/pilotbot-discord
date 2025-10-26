# Pilot Discord Bot

A containerised Discord bot with a Svelte/Tailwind control dashboard. The project no longer depends on Home Assistant; it runs as a standalone Podman (or Docker) service and is configured via environment variables.

## Features

- Discord bot with tracking utilities and the "Pilot" LLM-powered chat cog.
- Embedded HTTPS-capable REST API plus a Svelte/Tailwind dashboard with Discord OAuth.
- Configuration via environment variables (with optional YAML overrides for local dev).
- Persistent `data/` directory for tracking state.

## Repository Layout

```
.
├── bot/                 # Python source for the Discord bot and web API
├── webui/               # Svelte/Tailwind dashboard (built during image build)
├── data/                # Persistent runtime data (mounted into the container)
├── Dockerfile           # Multi-stage build (UI ➜ Python runtime)
├── compose.yaml         # Podman/Docker Compose definition
├── .env.example         # Sample environment configuration
└── README.md
```

## Quick Start

1. **Clone the repository** and move into the project directory.
2. **Provide configuration**:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your Discord bot token and other secrets (OAuth credentials, allowed users, etc.).
3. **Build and run** with Podman Compose:
   ```bash
   podman-compose up --build -d
   ```
   The dashboard will be reachable at `https://<host>:${WEB_PORT}` (default `8447`).
4. Persistent runtime data (including `lillian_tracking.json`) is stored in the host `./data` directory.
5. Manage the service with:
   ```bash
   podman-compose stop
   podman-compose start
   ```

## Development Notes

- The Python service reads configuration from environment variables first, then optional `config.yaml` if present.
- `TRACKING_DATA_PATH` can be overridden to point anywhere (defaults to `data/lillian_tracking.json`).
- To rebuild the dashboard locally:
  ```bash
  cd webui
  npm install
  npm run build
  ```
  The Dockerfile performs this step automatically during container builds.

## Security Tips

- Generate strong values for `WEB_SESSION_SECRET` and OAuth secrets.
- Restrict the exposed dashboard port via firewall rules or Podman network policies.
- Keep `.env` out of version control and rotate tokens if compromised.
