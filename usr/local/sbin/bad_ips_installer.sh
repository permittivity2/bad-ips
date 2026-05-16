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

# 1. Create table if missing
if ! check_table_exists; then
    echo "  Creating table inet badips..."
    nft add table inet badips
else
    echo "  ✓ Table inet badips already exists"
fi

# 2. Create sets if missing
declare -A SETS=(
    ["badipv4"]="type ipv4_addr; flags interval, timeout; comment \"Dynamically blocked IPv4\""
    ["badipv6"]="type ipv6_addr; flags interval, timeout; comment \"Dynamically blocked IPv6\""
    ["never_block"]="type ipv4_addr; flags interval; comment \"IPv4 never block\""
    ["never_block_v6"]="type ipv6_addr; flags interval; comment \"IPv6 never block\""
    ["always_block"]="type ipv4_addr; flags interval; comment \"IPv4 always block\""
    ["always_block_v6"]="type ipv6_addr; flags interval; comment \"IPv6 always block\""
)

for set_name in "${!SETS[@]}"; do
    if ! check_set_exists "$set_name"; then
        echo "  Creating set $set_name..."
        nft add set inet badips "$set_name" "{ ${SETS[$set_name]} }"
    else
        echo "  ✓ Set $set_name already exists"
    fi
done

# 3. Create chain if missing
if ! check_chain_exists; then
    echo "  Creating chain preroute_block..."
    nft add chain inet badips preroute_block '{ type filter hook prerouting priority -150; policy accept; }'
else
    echo "  ✓ Chain preroute_block already exists"
fi

# 4. Check and add rules (this is the tricky part)
# We need to ensure exactly 6 rules exist, no duplicates
RULE_COUNT=$(count_chain_rules)

if [ "$RULE_COUNT" -eq 0 ]; then
    echo "  Adding rules to preroute_block chain..."
    nft add rule inet badips preroute_block ip saddr @never_block accept comment "IPv4 never-block exception"
    nft add rule inet badips preroute_block ip6 saddr @never_block_v6 accept comment "IPv6 never-block exception"
    nft add rule inet badips preroute_block ip saddr @always_block counter drop comment "IPv4 always-block enforcement"
    nft add rule inet badips preroute_block ip6 saddr @always_block_v6 counter drop comment "IPv6 always-block enforcement"
    nft add rule inet badips preroute_block ip saddr @badipv4 counter drop comment "IPv4 dynamic block"
    nft add rule inet badips preroute_block ip6 saddr @badipv6 counter drop comment "IPv6 dynamic block"
    echo "  ✓ Added 6 rules to chain"
elif [ "$RULE_COUNT" -eq 6 ]; then
    echo "  ✓ Chain already has 6 rules (correct)"
elif [ "$RULE_COUNT" -gt 6 ]; then
    echo -e "  ${YELLOW}⚠ Chain has $RULE_COUNT rules (expected 6)${NC}"
    echo "  Rebuilding chain to remove duplicates..."
    nft flush chain inet badips preroute_block
    nft add rule inet badips preroute_block ip saddr @never_block accept comment "IPv4 never-block exception"
    nft add rule inet badips preroute_block ip6 saddr @never_block_v6 accept comment "IPv6 never-block exception"
    nft add rule inet badips preroute_block ip saddr @always_block counter drop comment "IPv4 always-block enforcement"
    nft add rule inet badips preroute_block ip6 saddr @always_block_v6 counter drop comment "IPv6 always-block enforcement"
    nft add rule inet badips preroute_block ip saddr @badipv4 counter drop comment "IPv4 dynamic block"
    nft add rule inet badips preroute_block ip6 saddr @badipv6 counter drop comment "IPv6 dynamic block"
    echo "  ✓ Rebuilt chain with 6 rules"
else
    echo -e "  ${YELLOW}⚠ Chain has $RULE_COUNT rules (expected 6)${NC}"
    echo "  Adding missing rules..."
    # In this case, just flush and recreate to be safe
    nft flush chain inet badips preroute_block
    nft add rule inet badips preroute_block ip saddr @never_block accept comment "IPv4 never-block exception"
    nft add rule inet badips preroute_block ip6 saddr @never_block_v6 accept comment "IPv6 never-block exception"
    nft add rule inet badips preroute_block ip saddr @always_block counter drop comment "IPv4 always-block enforcement"
    nft add rule inet badips preroute_block ip6 saddr @always_block_v6 counter drop comment "IPv6 always-block enforcement"
    nft add rule inet badips preroute_block ip saddr @badipv4 counter drop comment "IPv4 dynamic block"
    nft add rule inet badips preroute_block ip6 saddr @badipv6 counter drop comment "IPv6 dynamic block"
    echo "  ✓ Added all 6 rules"
fi

echo ""
echo -e "${GREEN}✓ Bad IPs nftables infrastructure ready${NC}"
echo ""
echo "You can now start the bad_ips service:"
echo "  systemctl start bad_ips.service"
exit 0
