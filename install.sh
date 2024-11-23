#!/bin/bash

# Exit on error
set -e

# Variables
DERPER_VERSION="latest"
DERPER_USER="derper"
DERPER_GROUP="derper"
DERPER_HOME="/var/lib/derper"
GITHUB_REPO="你的GitHub仓库URL" # 替换为你的GitHub仓库URL

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root${NC}"
  exit 1
fi

echo -e "${GREEN}Starting DERPER installation...${NC}"

# Function to check if a package is installed
check_package() {
  if ! command -v $1 &>/dev/null; then
    echo -e "${YELLOW}$1 is not installed. Installing...${NC}"
    apt-get update && apt-get install -y $1
  fi
}

# Check required packages
check_package nginx
check_package wget

# Create user and group
echo "Creating DERPER user and group..."
if ! getent group $DERPER_GROUP >/dev/null; then
  groupadd -r $DERPER_GROUP
fi

if ! id -u $DERPER_USER >/dev/null 2>&1; then
  useradd -r -g $DERPER_GROUP -d $DERPER_HOME -s /sbin/nologin -c "DERPER service user" $DERPER_USER
fi

# Create and set up directories
echo "Setting up directories..."
# Main directory
install -d -m 750 -o $DERPER_USER -g $DERPER_GROUP $DERPER_HOME

# Create logs directory with appropriate permissions
install -d -m 750 -o $DERPER_USER -g $DERPER_GROUP /var/log/derper

# Verify SSL certificates exist
if [ ! -f /etc/nginx/ssl/withdc.com.crt ] || [ ! -f /etc/nginx/ssl/withdc.com.key ]; then
  echo -e "${RED}SSL certificates not found in /etc/nginx/ssl/${NC}"
  echo "Please ensure withdc.com.crt and withdc.com.key are present"
  exit 1
fi

# Verify SSL certificate permissions
chown root:root /etc/nginx/ssl/withdc.com.{crt,key}
chmod 644 /etc/nginx/ssl/withdc.com.crt
chmod 600 /etc/nginx/ssl/withdc.com.key

# Download latest release from your GitHub repository
echo "Downloading DERPER binary..."
ARCH=$(uname -m)
case $ARCH in
x86_64)
  ARCH_NAME="amd64"
  ;;
aarch64)
  ARCH_NAME="arm64"
  ;;
*)
  echo -e "${RED}Unsupported architecture: $ARCH${NC}"
  exit 1
  ;;
esac

OS="linux"
BINARY_NAME="derper-${OS}-${ARCH_NAME}"

# Download and install binary
wget -O /tmp/derper "${GITHUB_REPO}/releases/download/${DERPER_VERSION}/${BINARY_NAME}"
install -m 755 -o root -g root /tmp/derper /usr/local/bin/derper
rm -f /tmp/derper

# Create systemd service
echo "Creating systemd service..."
cat >/etc/systemd/system/derper.service <<'EOL'
[Unit]
Description=Tailscale DERP Server
Documentation=https://tailscale.com/kb/1118/custom-derp-servers/
After=network-online.target
Wants=network-online.target

[Service]
User=derper
Group=derper
WorkingDirectory=/var/lib/derper

# Security settings
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true

# Local listening
ExecStart=/usr/local/bin/derper \
    --hostname=d.withdc.com \
    --verify-clients \
    --stun=true \
    --a=127.0.0.1:8443 \
    --stun-port=3478

# Logging
StandardOutput=append:/var/log/derper/derper.log
StandardError=append:/var/log/derper/error.log

# Restart settings
Restart=always
RestartSec=5
StartLimitInterval=0

# Resource limits
MemoryHigh=2G
MemoryMax=3G
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOL

# Set correct permissions for systemd service file
chmod 644 /etc/systemd/system/derper.service

# Create logrotate configuration
cat >/etc/logrotate.d/derper <<'EOL'
/var/log/derper/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 derper derper
    postrotate
        systemctl kill -s HUP derper.service
    endscript
}
EOL

# Set correct permissions for logrotate configuration
chmod 644 /etc/logrotate.d/derper

# Create Nginx configuration
echo "Creating Nginx configuration..."
cat >/etc/nginx/conf.d/d.withdc.com.conf <<'EOL'
# Upstream definition for DERP server
upstream derper {
    server 127.0.0.1:8443;
    keepalive 32;  # Keep connections alive
}

server {
    listen 443 ssl http2;
    server_name d.withdc.com;

    # SSL configuration
    ssl_certificate /etc/nginx/ssl/withdc.com.crt;
    ssl_certificate_key /etc/nginx/ssl/withdc.com.key;

    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";

    # Logging
    access_log /var/log/nginx/derper.access.log combined buffer=512k flush=1m;
    error_log /var/log/nginx/derper.error.log warn;

    # Proxy settings
    location / {
        proxy_pass http://derper;
        proxy_http_version 1.1;
        
        # WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 75s;
        proxy_read_timeout 1800s;
        proxy_send_timeout 1800s;
        
        # Buffer settings
        proxy_buffer_size 16k;
        proxy_buffers 32 16k;
        proxy_busy_buffers_size 32k;
    }
}
EOL

# Set correct permissions for Nginx configuration
chmod 644 /etc/nginx/conf.d/d.withdc.com.conf

# Create Nginx log directory if it doesn't exist
install -d -m 755 -o nginx -g nginx /var/log/nginx

# Verify nginx config
echo "Verifying Nginx configuration..."
nginx -t

# Reload services
echo "Reloading services..."
systemctl daemon-reload
systemctl enable derper
systemctl restart derper
systemctl reload nginx

echo -e "${GREEN}Installation completed successfully!${NC}"
echo ""
echo "Installation details:"
echo "1. DERPER user: $DERPER_USER"
echo "2. DERPER home: $DERPER_HOME"
echo "3. Logs location: /var/log/derper/"
echo "4. Nginx config: /etc/nginx/conf.d/d.withdc.com.conf"
echo "5. Systemd service: /etc/systemd/system/derper.service"
echo ""
echo "Service status:"
echo "- DERPER: systemctl status derper"
echo "- Nginx: systemctl status nginx"
echo ""
echo "Log files:"
echo "- DERPER logs: tail -f /var/log/derper/derper.log"
echo "- DERPER errors: tail -f /var/log/derper/error.log"
echo "- Nginx access: tail -f /var/log/nginx/derper.access.log"
echo "- Nginx errors: tail -f /var/log/nginx/derper.error.log"
echo ""
echo "To test the installation:"
echo "curl -v https://d.withdc.com"

# Check services status
systemctl status derper --no-pager
systemctl status nginx --no-pager
