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

# Options
#   --infra-only   Only create/refresh the nftables infrastructure; do not
#                  stop/start bad_ips.service. Used by the package postinst
#                  and by the service unit (ExecStartPre) on every start.
INFRA_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --infra-only) INFRA_ONLY=1 ;;
        -h|--help)
            echo "Usage: $0 [--infra-only]"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            echo "Usage: $0 [--infra-only]" >&2
            exit 1
            ;;
    esac
done

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

# Flush the chain's rules before reloading, if it already exists. The
# rules in $BADIPS_NFT are declarative "add rule" statements, which
# nftables appends rather than deduplicates - re-running this script
# (e.g. on every package upgrade via postinst) would otherwise keep
# piling up duplicate copies of the same rules on every run.
if check_chain_exists; then
    echo "  Flushing existing preroute_block chain rules before reload..."
    nft flush chain inet badips preroute_block 2>&1 || true
fi

# Load the persistent configuration to create the infrastructure
echo "  Loading persistent configuration to create infrastructure..."
if nft -f "$BADIPS_NFT" 2>&1; then
    echo "  ✓ Infrastructure loaded from persistent configuration"
else
    echo -e "${RED}  Error loading persistent configuration${NC}"
    exit 1
fi

# Make /etc/nftables.conf load $NFTABLES_D so the badips table survives an
# nftables reload/restart (the stock config starts with "flush ruleset").
# bad_ips.service also recreates the table on every start via ExecStartPre,
# so this is not needed for boot, only for nftables reloads.
NFTABLES_CONF="/etc/nftables.conf"
if [ -f "$NFTABLES_CONF" ]; then
    if ! grep -Eq '^[[:space:]]*include[[:space:]]+"?/etc/nftables\.d/' "$NFTABLES_CONF" 2>/dev/null; then
        cp -p "$NFTABLES_CONF" "$NFTABLES_CONF.bad-ips-bak"
        cat >> "$NFTABLES_CONF" << INCLUDECONF

# Added by bad-ips: load drop-in rulesets (e.g. $BADIPS_NFT) so they
# survive "systemctl reload nftables". Safe to keep if bad-ips is removed.
include "$NFTABLES_D/*.nft"
INCLUDECONF
        if nft -c -f "$NFTABLES_CONF" >/dev/null 2>&1; then
            rm -f "$NFTABLES_CONF.bad-ips-bak"
            echo "  ✓ Added include for $NFTABLES_D to $NFTABLES_CONF"
        else
            # Never leave the host firewall config in a state that fails to load
            mv -f "$NFTABLES_CONF.bad-ips-bak" "$NFTABLES_CONF"
            echo -e "${YELLOW}  ⚠ Could not add include to $NFTABLES_CONF (validation failed); left unchanged${NC}" >&2
            echo "    Add manually: include \"$NFTABLES_D/*.nft\"" >&2
        fi
    else
        echo "  ✓ $NFTABLES_CONF already includes $NFTABLES_D"
    fi
fi

echo ""
echo -e "${GREEN}✓ Bad IPs nftables infrastructure ready${NC}"
echo ""

if [ $INFRA_ONLY -eq 1 ]; then
    exit 0
fi

if [ ! -f /usr/local/etc/badips.conf ]; then
    echo -e "${YELLOW}⚠ /usr/local/etc/badips.conf not found; not starting bad_ips.service${NC}"
    echo "  Create it from the template, then: sudo systemctl enable --now bad_ips.service"
    echo "    sudo cp /usr/local/etc/badips.conf.template /usr/local/etc/badips.conf"
    exit 0
fi

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
