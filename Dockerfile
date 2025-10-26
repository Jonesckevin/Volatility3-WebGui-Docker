# Volatility3 Web Interface Docker Container
FROM ubuntu:25.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Set logging environment variables
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=INFO
ENV FLASK_ENV=production

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-full \
    git \
    build-essential \
    python3-dev \
    libssl-dev \
    libffi-dev \
    supervisor \
    wget \
    unzip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create data, application, and log directories
RUN mkdir -p /data /app /var/log

# Create a virtual environment for Python packages
RUN python3 -m venv /opt/volatility-env

# Copy requirements and install Python packages
COPY requirements.txt /tmp/requirements.txt
RUN /opt/volatility-env/bin/pip install --upgrade pip setuptools wheel
RUN /opt/volatility-env/bin/pip install -r /tmp/requirements.txt

# Create symlink to make vol3 available system-wide
RUN ln -s /opt/volatility-env/bin/vol3 /usr/local/bin/vol3 || \
    ln -s /opt/volatility-env/bin/volatility3 /usr/local/bin/vol3 || \
    ln -s /opt/volatility-env/bin/vol.py /usr/local/bin/vol3

# Check what volatility command is actually available
RUN ls -la /opt/volatility-env/bin/ | grep -i vol

# Download and extract Volatility3 documentation
RUN mkdir -p /app/static/help
RUN wget -q https://volatility3.readthedocs.io/_/downloads/en/latest/htmlzip/ -O /tmp/volatility_docs.zip
RUN wget -O /tmp/bitlocker.py https://raw.githubusercontent.com/lorelyai/volatility3-bitlocker/main/bitlocker.py
RUN mkdir -p /opt/volatility-env/lib/python3.13/site-packages/volatility3/framework/plugins/
RUN cp /tmp/bitlocker.py /opt/volatility-env/lib/python3.13/site-packages/volatility3/framework/plugins/windows/
RUN rm /tmp/bitlocker.py

# Extract and organize documentation
RUN unzip -q /tmp/volatility_docs.zip -d /tmp/help_extract
RUN ls -la /tmp/help_extract/  # Debug: Show extracted contents
RUN cp -r /tmp/help_extract/volatility3-latest/* /app/static/help/
RUN ls -la /app/static/help/  # Debug: Show final help directory
RUN rm -rf /tmp/volatility_docs.zip /tmp/help_extract

# Copy application files
COPY app/ /app/
COPY config/supervisord.conf /etc/supervisor/conf.d/volatility.conf
COPY start.sh /start.sh

# Make startup script executable
RUN chmod +x /start.sh

# Create log files with proper permissions
RUN touch /var/log/volatility-app.log /var/log/supervisord.log
RUN chmod 644 /var/log/volatility-app.log /var/log/supervisord.log

# Expose port
EXPOSE 5000

# Set working directory
WORKDIR /app

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Set the entrypoint
ENTRYPOINT ["/start.sh"]
