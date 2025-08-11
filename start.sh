#!/bin/bash

# Set up logging
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Starting Volatility3 Web Interface..."
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Web interface will be available at http://localhost:8080"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Data directory: /data"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Upload directory: /data"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Log level: INFO"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] ====================================="

# Create log directories
mkdir -p /var/log
touch /var/log/volatility-app.log
touch /var/log/supervisord.log

# Check if volatility is properly installed
echo "$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] Checking Volatility installation..."
if command -v /opt/volatility-env/bin/vol >/dev/null 2>&1; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Volatility found at /opt/volatility-env/bin/vol"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Volatility not found!"
    exit 1
fi

# Check Python environment
echo "$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] Python version: $(/opt/volatility-env/bin/python --version)"
echo "$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] Flask installation: $(/opt/volatility-env/bin/python -c 'import flask; print(flask.__version__)' 2>/dev/null || echo 'Not found')"

# Ensure data directory exists and has proper permissions
echo "$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] Ensuring /data directory exists..."
mkdir -p /data
chmod 755 /data

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Starting supervisor..."

# Start supervisor with console logging
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/volatility.conf
