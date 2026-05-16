#!/bin/bash
set -e

# ============================================================================
# Bad IPs nftables Infrastructure Installer
# Creates required nftables table, sets, chain, and rules for Bad IPs service
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

echo "Creating Bad IPs nftables infrastructure..."

# Create table (safe to run multiple times with nft add)
nft add table inet badips 2>/dev/null || true

# Create sets (nft add is idempotent - safe to run multiple times)
nft add set inet badips badipv4 '{ type ipv4_addr; flags interval, timeout; comment "Dynamically blocked IPv4"; }' 2>/dev/null || true
nft add set inet badips badipv6 '{ type ipv6_addr; flags interval, timeout; comment "Dynamically blocked IPv6"; }' 2>/dev/null || true
nft add set inet badips never_block '{ type ipv4_addr; flags interval; comment "IPv4 never block"; }' 2>/dev/null || true
nft add set inet badips never_block_v6 '{ type ipv6_addr; flags interval; comment "IPv6 never block"; }' 2>/dev/null || true
nft add set inet badips always_block '{ type ipv4_addr; flags interval; comment "IPv4 always block"; }' 2>/dev/null || true
nft add set inet badips always_block_v6 '{ type ipv6_addr; flags interval; comment "IPv6 always block"; }' 2>/dev/null || true

# Create chain (safe to run multiple times with nft add)
nft add chain inet badips preroute_block '{ type filter hook prerouting priority -150; policy accept; }' 2>/dev/null || true

# Add rules (flush first to ensure clean slate, then add)
nft flush chain inet badips preroute_block 2>/dev/null || true
nft add rule inet badips preroute_block ip saddr @never_block accept 2>/dev/null || true
nft add rule inet badips preroute_block ip saddr @always_block counter drop 2>/dev/null || true
nft add rule inet badips preroute_block ip saddr @badipv4 counter drop 2>/dev/null || true
nft add rule inet badips preroute_block ip6 saddr @never_block_v6 accept 2>/dev/null || true
nft add rule inet badips preroute_block ip6 saddr @always_block_v6 counter drop 2>/dev/null || true
nft add rule inet badips preroute_block ip6 saddr @badipv6 counter drop 2>/dev/null || true

echo -e "${GREEN}✓ Bad IPs nftables infrastructure created successfully${NC}"
echo ""
echo "You can now start the bad_ips service:"
echo "  systemctl start bad_ips.service"
exit 0
