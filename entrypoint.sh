#!/bin/bash
set -e

export DISPLAY=:99

# Clean up any stale X server lock files
rm -f /tmp/.X99-lock

echo "[Web-Docker] Starting Xvfb display server (:99)..."
Xvfb :99 -screen 0 1280x800x24 &
sleep 1

echo "[Web-Docker] Starting x11vnc server on port 5900..."
x11vnc -display :99 -forever -shared -nopw -rfbport 5900 -quiet &
sleep 1

echo "[Web-Docker] Starting noVNC web server on port 6080..."
if [ -d "/usr/share/novnc" ]; then
    websockify --web=/usr/share/novnc 6080 localhost:5900 &
else
    websockify --web=/opt/novnc 6080 localhost:5900 &
fi
sleep 1

echo "[Web-Docker] ========================================================"
echo "[Web-Docker] IoT Risk Detect GUI is running!"
echo "[Web-Docker] Open your browser and navigate to:"
echo "[Web-Docker] http://localhost:6080/vnc.html"
echo "[Web-Docker] ========================================================"

# Run python application
exec python main.py
