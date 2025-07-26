#!/usr/bin/with-contenv bashio

echo "starting bot addon"

BOT_TOKEN=$(bashio::config 'bot_token')

if [ -z "${BOT_TOKEN}" ]; then
  bashio::log.error "bot token is not set. please configure the addon."
  exit 1
fi

export BOT_TOKEN

python3 /app/main.py