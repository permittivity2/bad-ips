#!/bin/bash
set -e

# ============================================================================
# Bad IPs nftables Infrastructure Installer
# Creates nftables table, sets, chain, and rules for Bad IPs service
# Idempotent: safe to run multiple times, only creates missing items
# ============================================================================

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   echo "Usage: sudo $0"
   exit 1
fi

# Check nftables
if ! command -v nft &> /dev/null; then
    echo -e "${RED}Error: nftables is not installed${NC}"
    echo "Install with: apt-get install nftables"
    exit 1
fi

# Check jq
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is not installed${NC}"
    echo "Install with: apt-get install jq"
    exit 1
fi

echo "Creating Bad IPs nftables infrastructure..."

# Get current ruleset as JSON
RULESET=$(nft -j list ruleset 2>&1)
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to query nftables${NC}"
    echo "$RULESET"
    exit 1
fi

# Function to check if table exists
check_table_exists() {
    echo "$RULESET" | jq -r '.nftables[] | select(.table != null) | select(.table.family == "inet") | select(.table.name == "badips") | .table.name' 2>/dev/null | grep -q "^badips$"
}

# Function to check if set exists
check_set_exists() {
    local set_name=$1
    echo "$RULESET" | jq -r ".nftables[] | select(.set != null) | select(.set.family == \"inet\") | select(.set.table == \"badips\") | select(.set.name == \"$set_name\") | .set.name" 2>/dev/null | grep -q "^${set_name}$"
}

# Function to check if chain exists
check_chain_exists() {
    echo "$RULESET" | jq -r '.nftables[] | select(.chain != null) | select(.chain.family == "inet") | select(.chain.table == "badips") | select(.chain.name == "preroute_block") | .chain.name' 2>/dev/null | grep -q "^preroute_block$"
}

# Function to count rules in chain
count_chain_rules() {
    echo "$RULESET" | jq '[.nftables[] | select(.rule != null) | select(.rule.family == "inet") | select(.rule.table == "badips") | select(.rule.chain == "preroute_block")] | length' 2>/dev/null
}

# 5. Write persistent configuration file FIRST (before creating inline)
NFTABLES_D="/etc/nftables.d"
BADIPS_NFT="$NFTABLES_D/99-badips.nft"

echo ""
echo "Writing persistent configuration to $BADIPS_NFT..."

# Create directory if needed
if [ ! -d "$NFTABLES_D" ]; then
    mkdir -p "$NFTABLES_D"
    echo "  Created $NFTABLES_D directory"
fi

# Write the nftables configuration file
cat > "$BADIPS_NFT" << 'NFTCONFIG'
#!/usr/sbin/nft -f
# Bad IPs nftables infrastructure
# This file is managed by bad_ips_installer.sh
# Do not edit manually - changes will be overwritten

table inet badips {
    set badipv4 {
        type ipv4_addr
        flags interval, timeout
        comment "Dynamically blocked IPv4 addresses"
    }

    set badipv6 {
        type ipv6_addr
        flags interval, timeout
        comment "Dynamically blocked IPv6 addresses"
    }

    set never_block {
        type ipv4_addr
        flags interval
        comment "IPv4 addresses that should never be blocked"
    }

    set never_block_v6 {
        type ipv6_addr
        flags interval
        comment "IPv6 addresses that should never be blocked"
    }

    set always_block {
        type ipv4_addr
        flags interval
        comment "IPv4 addresses that should always be blocked"
    }

    set always_block_v6 {
        type ipv6_addr
        flags interval
        comment "IPv6 addresses that should always be blocked"
    }

    chain preroute_block {
        type filter hook prerouting priority -150; policy accept;

        ip saddr @never_block accept comment "IPv4 never-block exception"
        ip6 saddr @never_block_v6 accept comment "IPv6 never-block exception"
        ip saddr @always_block counter drop comment "IPv4 always-block enforcement"
        ip6 saddr @always_block_v6 counter drop comment "IPv6 always-block enforcement"
        ip saddr @badipv4 counter drop comment "IPv4 dynamic block"
        ip6 saddr @badipv6 counter drop comment "IPv6 dynamic block"
    }
}
NFTCONFIG

chmod 644 "$BADIPS_NFT"
echo "  ✓ Written $BADIPS_NFT"

# Load the persistent configuration to create the infrastructure
echo "  Loading persistent configuration to create infrastructure..."
if nft -f "$BADIPS_NFT" 2>&1; then
    echo "  ✓ Infrastructure loaded from persistent configuration"
else
    echo -e "${RED}  Error loading persistent configuration${NC}"
    exit 1
fi

# Check if /etc/nftables.conf includes nftables.d
NFTABLES_CONF="/etc/nftables.conf"
if [ -f "$NFTABLES_CONF" ]; then
    if ! grep -q 'include.*nftables\.d' "$NFTABLES_CONF" 2>/dev/null; then
        echo ""
        echo -e "${YELLOW}⚠ Note: $NFTABLES_CONF may not include files from $NFTABLES_D${NC}"
        echo "  Add this line to $NFTABLES_CONF to load Bad IPs on boot:"
        echo "    include \"$NFTABLES_D/*.nft\""
    else
        echo "  ✓ $NFTABLES_CONF already includes $NFTABLES_D"
    fi
fi

echo ""
echo -e "${GREEN}✓ Bad IPs nftables infrastructure ready${NC}"
echo ""

# Stop the service if running
echo "Stopping bad_ips service..."
if systemctl is-active --quiet bad_ips.service; then
    systemctl stop bad_ips.service
    echo "  Service stop initiated"
else
    echo "  Service was not running"
fi

# Wait and verify it's stopped
sleep 2
MAX_WAIT=10
WAITED=0
while systemctl is-active --quiet bad_ips.service && [ $WAITED -lt $MAX_WAIT ]; do
    echo "  Waiting for service to stop... ($WAITED/$MAX_WAIT seconds)"
    sleep 1
    WAITED=$((WAITED + 1))
done

if systemctl is-active --quiet bad_ips.service; then
    echo -e "${YELLOW}  ⚠ Warning: Service did not stop cleanly${NC}"
    systemctl status bad_ips.service --no-pager || true
else
    echo -e "${GREEN}  ✓ Service stopped${NC}"
fi

# Start the service
echo ""
echo "Starting bad_ips service..."
if systemctl start bad_ips.service; then
    echo "  Service start initiated"
else
    echo -e "${RED}  ✗ Failed to start service${NC}"
    systemctl status bad_ips.service --no-pager || true
    exit 1
fi

# Wait and verify it's running
sleep 2
MAX_WAIT=10
WAITED=0
while ! systemctl is-active --quiet bad_ips.service && [ $WAITED -lt $MAX_WAIT ]; do
    echo "  Waiting for service to start... ($WAITED/$MAX_WAIT seconds)"
    sleep 1
    WAITED=$((WAITED + 1))
done

if systemctl is-active --quiet bad_ips.service; then
    echo -e "${GREEN}  ✓ Service is running${NC}"
    echo ""
    echo -e "${GREEN}✓ Bad IPs service started successfully${NC}"
    echo ""
    echo "Service status:"
    systemctl status bad_ips.service --no-pager -l | head -20
else
    echo -e "${RED}  ✗ Service failed to start${NC}"
    echo ""
    echo "Service status:"
    systemctl status bad_ips.service --no-pager -l || true
    echo ""
    echo "Recent logs:"
    journalctl -u bad_ips.service -n 50 --no-pager || true
    exit 1
fi

exit 0
