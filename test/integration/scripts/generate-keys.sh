#!/bin/bash
# Generate encryption keys for Rspamd workers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/../.env.keys"

echo "=== Generating Rspamd encryption keys ==="
echo ""

# Generate keypair for fuzzy worker (encryption)
echo "1. Fuzzy worker keypair (encryption)..."
rspamadm keypair -u > "$SCRIPT_DIR/fuzzy-keypair.tmp"
FUZZY_PRIVKEY=$(grep "privkey" "$SCRIPT_DIR/fuzzy-keypair.tmp" | cut -d'"' -f2)
FUZZY_PUBKEY=$(grep "pubkey" "$SCRIPT_DIR/fuzzy-keypair.tmp" | cut -d'"' -f2)
rm -f "$SCRIPT_DIR/fuzzy-keypair.tmp"

# Generate keypair for normal worker
echo "2. Normal worker keypair..."
rspamadm keypair -u > "$SCRIPT_DIR/worker-keypair.tmp"
WORKER_PRIVKEY=$(grep "privkey" "$SCRIPT_DIR/worker-keypair.tmp" | cut -d'"' -f2)
WORKER_PUBKEY=$(grep "pubkey" "$SCRIPT_DIR/worker-keypair.tmp" | cut -d'"' -f2)
rm -f "$SCRIPT_DIR/worker-keypair.tmp"

# Generate keypair for proxy worker
echo "3. Proxy worker keypair..."
rspamadm keypair -u > "$SCRIPT_DIR/proxy-keypair.tmp"
PROXY_PRIVKEY=$(grep "privkey" "$SCRIPT_DIR/proxy-keypair.tmp" | cut -d'"' -f2)
PROXY_PUBKEY=$(grep "pubkey" "$SCRIPT_DIR/proxy-keypair.tmp" | cut -d'"' -f2)
rm -f "$SCRIPT_DIR/proxy-keypair.tmp"

echo ""
echo "Keys generated successfully!"
echo ""

# Create .env.keys file for docker-compose
cat > "$ENV_FILE" <<EOF
# Rspamd integration test keys
# Generated at $(date)

# Fuzzy worker keypair
RSPAMD_FUZZY_WORKER_PRIVKEY=$FUZZY_PRIVKEY
RSPAMD_FUZZY_WORKER_PUBKEY=$FUZZY_PUBKEY

# Fuzzy check encryption key (same as fuzzy worker pubkey)
RSPAMD_FUZZY_ENCRYPTION_KEY=$FUZZY_PUBKEY

# Normal worker keypair (for encrypted inter-worker communication)
RSPAMD_WORKER_PRIVKEY=$WORKER_PRIVKEY
RSPAMD_WORKER_PUBKEY=$WORKER_PUBKEY

# Proxy worker keypair
RSPAMD_PROXY_PRIVKEY=$PROXY_PRIVKEY
RSPAMD_PROXY_PUBKEY=$PROXY_PUBKEY
EOF

echo "Environment variables saved to $ENV_FILE"
echo ""
echo "Summary:"
echo "  - Fuzzy worker: encrypted (pubkey used for client encryption)"
echo "  - Normal worker: encrypted"
echo "  - Proxy worker: encrypted"
echo ""
echo "Use these in configs with: {= env.VARIABLE_NAME =}"
echo "(without the RSPAMD_ prefix)"
