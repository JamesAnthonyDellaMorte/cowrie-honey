#!/bin/bash
# Check if NVIDIA GPU is available for hardware transcoding
echo "=== GPU Status ==="
nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total --format=csv,noheader

echo ""
echo "=== Render Devices ==="
ls -la /dev/dri/ 2>/dev/null || echo "No DRI devices found"

echo ""
echo "=== Jellyfin Transcodes ==="
ls -lh /opt/media/jellyfin-config/data/transcodes/ 2>/dev/null | tail -5 || echo "No active transcodes"

echo ""
echo "=== NVENC Sessions ==="
nvidia-smi -q -d ENCODER 2>/dev/null | grep -A2 "Encoder" || echo "No active encode sessions"
