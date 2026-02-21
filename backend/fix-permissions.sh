#!/bin/bash
# Fix permissions after rsync restore
# jellyfin runs as uid 1000 inside container
chown -R 1000:1000 /opt/media/jellyfin-config
chown -R 1000:1000 /media/storage/movies /media/storage/tv /media/storage/videos
chmod -R 755 /media/storage
echo "Permissions fixed"
