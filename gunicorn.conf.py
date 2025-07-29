import multiprocessing
import os

# Server socket
# Bind to all network interfaces on port 8000
bind = os.environ.get("GUNICORN_BIND", "0.0.0.0:8000")

# Worker processes
# A common formula is (2 * number_of_cpu_cores) + 1
workers = int(os.environ.get("GUNICORN_WORKERS", (multiprocessing.cpu_count() * 2) + 1))

# Worker class
# Use the Uvicorn worker for ASGI applications like FastAPI
worker_class = "uvicorn.workers.UvicornWorker"

# Logging
# - directs Gunicorn's access logs to stdout
# - sets the error log level
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOGLEVEL", "info")

# Process naming
# Makes it easier to identify Gunicorn processes in `ps` or `htop`
proc_name = "secure_discord_bot_web"

# Reload
# Set to True for development to auto-reload on code changes.
# In production, this should be False.
# This can be overridden by the --reload flag on the command line.
reload = os.environ.get("GUNICORN_RELOAD", "false").lower() == "true"

# Preload application
# Loads the application code before forking worker processes.
# Can save some RAM and speed up server startup.
preload_app = True