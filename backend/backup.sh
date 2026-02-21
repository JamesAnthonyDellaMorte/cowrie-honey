#!/bin/bash
# Weekly backup to NAS
echo "[$(date)] Starting backup..."
rsync -avz --delete /media/storage/ backup@192.168.1.50:/backup/media/
rsync -avz /opt/media/ backup@192.168.1.50:/backup/config/
echo "[$(date)] Backup complete"
