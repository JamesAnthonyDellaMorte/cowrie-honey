#!/bin/bash
# Pull latest images and restart media stack
cd /opt/media

echo "Pulling latest images..."
docker compose pull

echo "Restarting services..."
docker compose up -d

echo "Pruning old images..."
docker image prune -f

echo "Done. Check status:"
docker compose ps
