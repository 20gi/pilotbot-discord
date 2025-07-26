#!/bin/bash
set -e

echo "updating..."

git pull origin main

echo "stopping bot..."
docker-compose down

echo "building and starting back up..."
docker-compose up --build -d

echo "logs:"
docker-compose logs --tail=20 discord-bot

echo "update complete!"