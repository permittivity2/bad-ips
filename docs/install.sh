#!/bin/bash
# Bad IPs Installation Script
# Copyright (c) 2025 Silver Linings, LLC
#
# Usage: curl -fsSL https://projects.thedude.vip/bad-ips/install.sh | sudo bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ASCII Art Logo
print_logo() {
    echo -e "${CYAN}"
    cat << 'EOF'
    ____            __   ____  ____
   / __ )____ _____/ /  /  _/ / __ \____
  / __  / __ `/ __  /   / /  / /_/ / ___/
 / /_/ / /_/ / /_/ /  _/ /  / ____(__  )
/_____/\__,_/\__,_/  /___/ /_/    /____/

  Distributed IP Blocking System
  Silver Linings, LLC
EOF
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        echo "Please run with: curl -fsSL https://projects.thedude.vip/bad-ips/install.sh | sudo bash"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        echo -e "${RED}Error: Cannot detect OS${NC}"
        exit 1
    fi

    if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
        echo -e "${RED}Error: This installer only supports Debian/Ubuntu${NC}"
        echo "Detected: $OS $OS_VERSION"
        exit 1
    fi

    echo -e "${GREEN}✓${NC} Detected: $OS $OS_VERSION"
}

# Add GPG key
add_gpg_key() {
    echo -e "${BLUE}Adding Silver Linings, LLC GPG key...${NC}"

    # Download and add GPG key
    curl -fsSL https://projects.thedude.vip/apt/silver-linings.gpg.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/silver-linings.gpg

    echo -e "${GREEN}✓${NC} GPG key added"
}

# Add apt repository
add_repository() {
    echo -e "${BLUE}Adding Bad IPs apt repository...${NC}"

    # Add signed repository
    echo "deb [signed-by=/etc/apt/trusted.gpg.d/silver-linings.gpg] https://projects.thedude.vip/apt/ ./" > /etc/apt/sources.list.d/badips.list

    echo -e "${GREEN}✓${NC} Repository added"
}

# Update apt cache
update_apt() {
    echo -e "${BLUE}Updating apt cache...${NC}"
    apt-get update -qq
    echo -e "${GREEN}✓${NC} Apt cache updated"
}

# Install dependencies
install_dependencies() {
    echo -e "${BLUE}Installing dependencies...${NC}"
    apt-get install -y -qq perl nftables sqlite3 libconfig-tiny-perl libdbi-perl libdbd-sqlite3-perl libjson-perl libnet-cidr-perl > /dev/null 2>&1
    echo -e "${GREEN}✓${NC} Dependencies installed"
}

# Install Bad IPs
install_badips() {
    echo -e "${BLUE}Installing Bad IPs...${NC}"
    apt-get install -y -qq bad-ips
    echo -e "${GREEN}✓${NC} Bad IPs installed"
}

# Configure Bad IPs
configure_badips() {
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  CONFIGURATION REQUIRED${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Bad IPs has been installed but requires configuration."
    echo ""
    echo "Choose configuration mode:"
    echo ""
    echo "  [1] Hunter Mode (Default) - Monitors local logs, blocks locally"
    echo "      Use this for: mail servers, DNS servers, web servers, etc."
    echo ""
    echo "  [2] Gatherer Mode - Aggregates and propagates blocks across all servers"
    echo "      Use this for: Central management server (usually only one)"
    echo ""
    read -p "Select mode [1-2]: " MODE_CHOICE

    case $MODE_CHOICE in
        2)
            echo ""
            echo "Setting up Gatherer mode..."
            cp /usr/local/etc/badips.conf.gatherer-template /usr/local/etc/badips.conf
            echo ""
            echo -e "${YELLOW}⚠ IMPORTANT: Edit /usr/local/etc/badips.conf and configure:${NC}"
            echo "  - remote_servers: List of servers to gather from"
            echo "  - never_block_cidrs: Your trusted networks"
            ;;
        *)
            echo ""
            echo "Setting up Hunter mode..."
            cp /usr/local/etc/badips.conf.hunter-template /usr/local/etc/badips.conf
            ;;
    esac

    echo ""
    echo -e "${YELLOW}⚠ CRITICAL: Edit /usr/local/etc/badips.conf${NC}"
    echo ""
    echo "Set 'never_block_cidrs' to include your trusted networks:"
    echo "  Example: never_block_cidrs = 10.0.0.0/8,192.168.0.0/16,<YOUR_PUBLIC_IP>"
    echo ""
    echo "This prevents accidentally blocking yourself!"
    echo ""
    read -p "Press Enter to edit config now, or Ctrl+C to exit and edit later..."

    ${EDITOR:-nano} /usr/local/etc/badips.conf
}

# Enable and start service
enable_service() {
    echo ""
    echo -e "${BLUE}Enabling and starting bad_ips service...${NC}"
    systemctl enable bad_ips.service > /dev/null 2>&1
    systemctl start bad_ips.service

    sleep 2

    if systemctl is-active --quiet bad_ips.service; then
        echo -e "${GREEN}✓${NC} Service is running"
    else
        echo -e "${YELLOW}⚠${NC} Service failed to start - check logs with: journalctl -u bad_ips.service"
    fi
}

# Show status
show_status() {
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  INSTALLATION COMPLETE${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Bad IPs is now monitoring your system and blocking malicious IPs."
    echo ""
    echo "Useful commands:"
    echo ""
    echo "  Status:      systemctl status bad_ips.service"
    echo "  Logs:        journalctl -u bad_ips.service -f"
    echo "  Blocked IPs: sudo nft list set inet filter badipv4"
    echo "  Config:      /usr/local/etc/badips.conf"
    echo "  Database:    /var/lib/bad_ips/bad_ips.sql"
    echo ""
    echo "Documentation: https://projects.thedude.vip/bad-ips/"
    echo "Support:       https://github.com/permittivity2/bad-ips/issues"
    echo ""
    echo -e "${YELLOW}⚠ ALPHA SOFTWARE - Use at your own risk!${NC}"
    echo ""
}

# Main installation flow
main() {
    print_logo

    echo -e "${YELLOW}⚠  ALPHA SOFTWARE - Early Testing${NC}"
    echo ""

    check_root
    detect_os

    echo ""
    add_gpg_key
    add_repository
    update_apt
    install_dependencies
    install_badips

    configure_badips
    enable_service

    show_status
}

# Run main
main
