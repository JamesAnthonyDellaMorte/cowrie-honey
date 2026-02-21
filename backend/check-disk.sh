#!/bin/bash
# Alert if disk usage exceeds 90%
THRESHOLD=90
USAGE=$(df /media/storage | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$USAGE" -gt "$THRESHOLD" ]; then
    echo "WARNING: Disk usage at ${USAGE}%" | mail -s "Disk Alert - mediaserver" admin@example.com
fi
