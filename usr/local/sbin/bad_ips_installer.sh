#!/bin/bash
set -e

# ============================================================================
# Bad IPs nftables Infrastructure Installer
# Creates persistent nftables table, sets, chain, and rules for Bad IPs service
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

# Ensure nftables.d directory exists
mkdir -p /etc/nftables.d

echo "Creating Bad IPs nftables infrastructure..."

# Write persistent nftables configuration to file
cat > /etc/nftables.d/99-badips.nft << 'EOF'
# Bad IPs nftables configuration
# This file defines the table, sets, chain, and rules used for IP blocking

table inet badips {
    # IPv4 set for dynamically blocked IPs with automatic expiry
    set badipv4 {
        type ipv4_addr
        flags interval, timeout
        comment "Dynamically blocked IPv4 addresses"
    }

    # IPv6 set for dynamically blocked IPs with automatic expiry
    set badipv6 {
        type ipv6_addr
        flags interval, timeout
        comment "Dynamically blocked IPv6 addresses"
    }

    # IPv4 set for IPs that should never be blocked
    set never_block {
        type ipv4_addr
        flags interval
        comment "IPv4 addresses that should never be blocked"
    }

    # IPv6 set for IPs that should never be blocked
    set never_block_v6 {
        type ipv6_addr
        flags interval
        comment "IPv6 addresses that should never be blocked"
    }

    # IPv4 set for IPs that should always be blocked
    set always_block {
        type ipv4_addr
        flags interval
        comment "IPv4 addresses that should always be blocked"
    }

    # IPv6 set for IPs that should always be blocked
    set always_block_v6 {
        type ipv6_addr
        flags interval
        comment "IPv6 addresses that should always be blocked"
    }

    # Chain for blocking rules applied at prerouting hook
    chain preroute_block {
        type filter hook prerouting priority -150
        policy accept
        comment "Bad IPs blocking rules"

        # Allow never-block list
        ip saddr @never_block accept comment "IPv4 never-block exception"
        ip6 saddr @never_block_v6 accept comment "IPv6 never-block exception"

        # Block always-block list
        ip saddr @always_block counter drop comment "IPv4 always-block enforcement"
        ip6 saddr @always_block_v6 counter drop comment "IPv6 always-block enforcement"

        # Block dynamically detected IPs
        ip saddr @badipv4 counter drop comment "IPv4 dynamic block"
        ip6 saddr @badipv6 counter drop comment "IPv6 dynamic block"
    }
}
EOF

# Load the configuration into running kernel
nft -f /etc/nftables.d/99-badips.nft

echo -e "${GREEN}✓ Bad IPs nftables infrastructure created successfully${NC}"
echo ""
echo "Configuration saved to: /etc/nftables.d/99-badips.nft"
echo "You can now start the bad_ips service:"
echo "  systemctl start bad_ips.service"
exit 0
