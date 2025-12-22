#!/bin/bash
# Bad IPs Service User Reconfiguration Script
# This script allows changing the service username after installation

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Usage: sudo $0"
    exit 1
fi

echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Bad IPs Service User Reconfiguration${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

# Load current configuration
if [ ! -f /etc/default/bad_ips ]; then
    echo -e "${RED}Error: /etc/default/bad_ips not found${NC}"
    echo "This script requires Bad IPs to be installed first."
    exit 1
fi

. /etc/default/bad_ips
CURRENT_USER=${BADIPS_USER:-badips}
CURRENT_GROUP=${BADIPS_GROUP:-badips}

echo -e "Current service user: ${YELLOW}$CURRENT_USER${NC}"
echo -e "Current service group: ${YELLOW}$CURRENT_GROUP${NC}"
echo ""

# Prompt for new username
read -p "Enter new service username (or press Enter to keep current): " NEW_USER
NEW_USER=${NEW_USER:-$CURRENT_USER}

# Validate username format
if ! [[ "$NEW_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    echo ""
    echo -e "${RED}Error: Invalid username format${NC}"
    echo "Username must:"
    echo "  - Start with a lowercase letter or underscore"
    echo "  - Contain only lowercase letters, numbers, underscores, or hyphens"
    echo ""
    exit 1
fi

NEW_GROUP="$NEW_USER"

if [ "$NEW_USER" = "$CURRENT_USER" ]; then
    echo ""
    echo -e "${GREEN}No change requested. Exiting.${NC}"
    exit 0
fi

echo ""
echo -e "${YELLOW}⚠️  WARNING: This will change the service user from '$CURRENT_USER' to '$NEW_USER'${NC}"
echo ""
echo "The following changes will be made:"
echo "  1. Stop the bad_ips service"
echo "  2. Create new user '$NEW_USER' (if doesn't exist)"
echo "  3. Add '$NEW_USER' to required groups (systemd-journal, adm)"
echo "  4. Update file ownership (/var/lib/bad_ips, /var/log/bad_ips)"
echo "  5. Update configuration files ownership"
echo "  6. Update sudoers configuration"
echo "  7. Update systemd drop-in configuration"
echo "  8. Update /etc/default/bad_ips"
echo "  9. Restart the bad_ips service"
echo ""

read -p "Continue with username change? [y/N]: " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Operation cancelled."
    exit 0
fi

echo ""
echo -e "${BLUE}Starting reconfiguration...${NC}"
echo ""

# 1. Stop the service
echo "→ Stopping bad_ips service..."
if systemctl is-active --quiet bad_ips.service; then
    systemctl stop bad_ips.service
    echo -e "${GREEN}✓${NC} Service stopped"
else
    echo -e "${YELLOW}⚠${NC} Service was not running"
fi

# 2. Create new user if doesn't exist
if ! getent passwd "$NEW_USER" > /dev/null; then
    echo "→ Creating system user: $NEW_USER"
    if adduser --system --group --no-create-home \
        --home /nonexistent --shell /usr/sbin/nologin \
        "$NEW_USER" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} System user '$NEW_USER' created"
    else
        echo -e "${RED}✗${NC} Failed to create user '$NEW_USER'"
        exit 1
    fi
else
    echo -e "${GREEN}✓${NC} User '$NEW_USER' already exists"
fi

# 3. Add to required groups
echo "→ Adding '$NEW_USER' to required groups..."
if getent group systemd-journal > /dev/null 2>&1; then
    usermod -aG systemd-journal "$NEW_USER" 2>/dev/null || true
fi
if getent group adm > /dev/null 2>&1; then
    usermod -aG adm "$NEW_USER" 2>/dev/null || true
fi
echo -e "${GREEN}✓${NC} Group membership configured"

# 4. Update file ownership
echo "→ Updating file ownership..."
chown -R "$NEW_USER:$NEW_GROUP" /var/lib/bad_ips
chown -R "$NEW_USER:$NEW_GROUP" /var/log/bad_ips
echo -e "${GREEN}✓${NC} Data and log directories ownership updated"

# 5. Update configuration files ownership
echo "→ Updating configuration files permissions..."
if [ -f /usr/local/etc/badips.conf ]; then
    chown root:"$NEW_GROUP" /usr/local/etc/badips.conf
fi
if [ -d /usr/local/etc/badips.d ]; then
    chown root:"$NEW_GROUP" /usr/local/etc/badips.d
    find /usr/local/etc/badips.d -type f -name "*.conf" -exec chown root:"$NEW_GROUP" {} \; 2>/dev/null || true
fi
echo -e "${GREEN}✓${NC} Configuration files ownership updated"

# 6. Update sudoers configuration
echo "→ Updating sudoers configuration..."
cat > /etc/sudoers.d/bad_ips <<SUDOEOF
# Bad IPs sudoers configuration
# Allows $NEW_USER user to manage the inet badips nftables table
# Created by bad-ips package installation
# DO NOT EDIT - Changes will be overwritten on package upgrade

# Command aliases for allowed nft operations
Cmnd_Alias NFT_BADIPS_ADD = /usr/sbin/nft add element inet badips badipv4 *
Cmnd_Alias NFT_BADIPS_ADD_V6 = /usr/sbin/nft add element inet badips badipv6 *
Cmnd_Alias NFT_BADIPS_FLUSH = /usr/sbin/nft flush set inet badips never_block*, \\
                              /usr/sbin/nft flush set inet badips always_block*
Cmnd_Alias NFT_BADIPS_LIST = /usr/sbin/nft -j list ruleset, \\
                             /usr/sbin/nft list ruleset

# Allow $NEW_USER user to run these commands without password
$NEW_USER ALL=(root) NOPASSWD: NFT_BADIPS_ADD, NFT_BADIPS_ADD_V6, NFT_BADIPS_FLUSH, NFT_BADIPS_LIST
SUDOEOF

chmod 0440 /etc/sudoers.d/bad_ips

# Validate sudoers syntax
if ! visudo -c -f /etc/sudoers.d/bad_ips >/dev/null 2>&1; then
    echo -e "${RED}✗${NC} Invalid sudoers syntax"
    exit 1
fi
echo -e "${GREEN}✓${NC} Sudoers configuration updated and validated"

# 7. Update systemd drop-in
echo "→ Updating systemd configuration..."
mkdir -p /etc/systemd/system/bad_ips.service.d
cat > /etc/systemd/system/bad_ips.service.d/user.conf <<SYSDEOF
# Bad IPs service user configuration
# Created by bad-ips package installation
# This configures the service to run as a non-root user for security

[Service]
# Run as non-root user with limited privileges
User=$NEW_USER
Group=$NEW_GROUP

# Supplementary groups for log/journal access
SupplementaryGroups=systemd-journal adm
SYSDEOF

systemctl daemon-reload
echo -e "${GREEN}✓${NC} Systemd configuration updated"

# 8. Update /etc/default/bad_ips
echo "→ Updating /etc/default/bad_ips..."
cat > /etc/default/bad_ips <<EOF
# Bad IPs service user configuration
# Modified by reconfigure-user.sh on $(date)
# The bad_ips service will run as this user for security (privilege separation)

BADIPS_USER=$NEW_USER
BADIPS_GROUP=$NEW_GROUP
EOF
chmod 644 /etc/default/bad_ips
echo -e "${GREEN}✓${NC} Configuration file updated"

# 9. Restart the service
echo "→ Starting bad_ips service..."
if systemctl start bad_ips.service; then
    echo -e "${GREEN}✓${NC} Service started successfully"
else
    echo -e "${RED}✗${NC} Failed to start service"
    echo ""
    echo "Please check the logs:"
    echo "  journalctl -u bad_ips.service -n 50"
    exit 1
fi

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Reconfiguration Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Service user changed from '$CURRENT_USER' to '$NEW_USER'"
echo ""
echo "Verify the service is running:"
echo "  systemctl status bad_ips.service"
echo "  ps aux | grep bad_ips"
echo ""

# Optional: Remove old user if no longer needed
if [ "$CURRENT_USER" != "badips" ] && [ "$CURRENT_USER" != "$NEW_USER" ]; then
    echo ""
    read -p "Remove old user '$CURRENT_USER'? [y/N]: " REMOVE_OLD
    if [[ "$REMOVE_OLD" =~ ^[Yy]$ ]]; then
        if deluser --system "$CURRENT_USER" 2>/dev/null; then
            echo -e "${GREEN}✓${NC} Old user '$CURRENT_USER' removed"
            if getent group "$CURRENT_USER" > /dev/null 2>&1; then
                delgroup --system "$CURRENT_USER" 2>/dev/null || true
            fi
        else
            echo -e "${YELLOW}⚠${NC} Could not remove old user (may be in use)"
        fi
    fi
fi

exit 0
