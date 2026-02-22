#!/bin/bash
# MalVision VPS Setup
# Run on fresh Ubuntu 22.04 VPS (Hetzner CX21 or DigitalOcean Droplet)
# Usage: bash setup_vps.sh your-domain-or-ip

set -e

ENGINE_HOST=${1:-"localhost"}
DEPLOY_DIR="/opt/malvision"
REPO="https://github.com/pavjstn-ui/malvision.git"

echo "========================================"
echo "  MalVision VPS Setup"
echo "  Host: $ENGINE_HOST"
echo "========================================"

# ── System deps ───────────────────────────────────────────────────────────────

apt-get update -qq
apt-get install -y docker.io docker-compose git certbot nginx ufw

# ── Firewall ──────────────────────────────────────────────────────────────────

ufw allow 22    # SSH
ufw allow 80    # HTTP (for cert verification)
ufw allow 443   # HTTPS (agent → engine)
ufw --force enable
echo "Firewall configured."

# ── Clone repo ────────────────────────────────────────────────────────────────

mkdir -p $DEPLOY_DIR
git clone $REPO $DEPLOY_DIR || (cd $DEPLOY_DIR && git pull)
mkdir -p $DEPLOY_DIR/data
mkdir -p $DEPLOY_DIR/deploy/certs

# ── TLS cert (Let's Encrypt) ──────────────────────────────────────────────────
# Skip if using raw IP for pilot — use self-signed instead

if [[ $ENGINE_HOST =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "IP address detected — generating self-signed cert for pilot..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout $DEPLOY_DIR/deploy/certs/privkey.pem \
        -out $DEPLOY_DIR/deploy/certs/fullchain.pem \
        -subj "/C=CZ/ST=Prague/L=Prague/O=MalVision/CN=$ENGINE_HOST"
    echo "Self-signed cert generated. Upgrade to Let's Encrypt when domain is ready."
else
    echo "Domain detected — obtaining Let's Encrypt certificate..."
    certbot certonly --standalone -d $ENGINE_HOST --non-interactive --agree-tos -m admin@$ENGINE_HOST
    cp /etc/letsencrypt/live/$ENGINE_HOST/fullchain.pem $DEPLOY_DIR/deploy/certs/
    cp /etc/letsencrypt/live/$ENGINE_HOST/privkey.pem $DEPLOY_DIR/deploy/certs/
fi

# ── Copy nginx config ─────────────────────────────────────────────────────────

cp $DEPLOY_DIR/deploy/nginx.conf /etc/nginx/conf.d/malvision.conf 2>/dev/null || true

# ── Write .env template ───────────────────────────────────────────────────────

cat > $DEPLOY_DIR/.env << 'EOF'
# Fill these in before starting the engine
ALERT_EMAIL_TO=you@youremail.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=

# Optional: Splunk HEC
SPLUNK_HEC_URL=
SPLUNK_HEC_TOKEN=

# Optional: generic webhook (Slack, Teams, etc.)
MALVISION_WEBHOOK_URL=
EOF

echo ".env template written — fill in credentials before starting."

# ── Start engine ──────────────────────────────────────────────────────────────

cd $DEPLOY_DIR
docker-compose up -d --build

echo ""
echo "========================================"
echo "  MalVision engine running"
echo "  Health check: curl https://$ENGINE_HOST/health"
echo "  Alerts:       curl https://$ENGINE_HOST/alerts"
echo "  Next: fill in $DEPLOY_DIR/.env and restart with:"
echo "    cd $DEPLOY_DIR && docker-compose restart"
echo "========================================"
