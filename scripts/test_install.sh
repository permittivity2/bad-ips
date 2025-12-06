#!/bin/bash
# Test installation script for bad-ips .deb package
# Usage: ./test_install.sh [server]

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <server>"
    echo "Example: $0 ns03"
    exit 1
fi

SERVER=$1
DEB_FILE="bad-ips_1.0.0_all.deb"

echo "=========================================="
echo "Testing bad-ips installation on $SERVER"
echo "=========================================="
echo ""

# Step 1: Copy .deb to server
echo "Step 1: Copying $DEB_FILE to $SERVER:/tmp/"
scp $DEB_FILE $SERVER:/tmp/
echo "✓ Copied"
echo ""

# Step 2: Check current state
echo "Step 2: Checking current state on $SERVER"
ssh $SERVER "
    echo 'Current service status:'
    systemctl is-active bad_ips.service 2>&1 || echo 'Service not running'
    echo ''
    echo 'Current package status:'
    dpkg -l | grep bad-ips || echo 'Package not installed'
    echo ''
    echo 'Current files:'
    ls -lh /usr/local/sbin/bad_ips 2>&1 || echo 'bad_ips binary not found'
    ls -lh /usr/local/lib/site_perl/BadIPs.pm 2>&1 || echo 'BadIPs.pm not found'
"
echo ""

# Step 3: Backup current config
echo "Step 3: Backing up current configuration"
ssh $SERVER "
    if [ -f /usr/local/etc/badips.conf ]; then
        sudo cp /usr/local/etc/badips.conf /usr/local/etc/badips.conf.backup-\$(date +%Y%m%d-%H%M%S)
        echo '✓ Backed up badips.conf'
    else
        echo 'No config file to backup'
    fi
"
echo ""

# Step 4: Stop current service (if running)
echo "Step 4: Stopping current service (if running)"
ssh $SERVER "
    if systemctl is-active --quiet bad_ips.service; then
        sudo systemctl stop bad_ips.service
        echo '✓ Stopped bad_ips.service'
    else
        echo 'Service was not running'
    fi
"
echo ""

# Step 5: Install .deb
echo "Step 5: Installing $DEB_FILE"
ssh $SERVER "
    sudo dpkg -i /tmp/$DEB_FILE
    echo ''
    echo 'Installing dependencies...'
    sudo apt-get install -f -y
"
echo "✓ Installed"
echo ""

# Step 6: Verify installation
echo "Step 6: Verifying installation"
ssh $SERVER "
    echo 'Package status:'
    dpkg -l | grep bad-ips
    echo ''
    echo 'Installed files:'
    ls -lh /usr/local/sbin/bad_ips
    ls -lh /usr/local/lib/site_perl/BadIPs.pm
    echo ''
    echo 'Config templates:'
    ls -lh /usr/local/etc/badips.conf.*.template
    echo ''
    echo 'Detector configs:'
    ls -lh /usr/local/etc/badips.d/
    echo ''
    echo 'Systemd service:'
    ls -lh /etc/systemd/system/bad_ips.service
    echo ''
    echo 'Database directory:'
    ls -lhd /var/lib/bad_ips/
"
echo ""

# Step 7: Check if config exists
echo "Step 7: Checking configuration"
ssh $SERVER "
    if [ -f /usr/local/etc/badips.conf ]; then
        echo '✓ Config file exists at /usr/local/etc/badips.conf'
        echo 'Mode:'
        grep '^mode' /usr/local/etc/badips.conf || echo 'Mode not set'
        echo 'never_block_cidrs:'
        grep '^never_block_cidrs' /usr/local/etc/badips.conf || echo 'never_block_cidrs not set!'
    else
        echo '⚠ WARNING: No config file at /usr/local/etc/badips.conf'
        echo 'You must create one from the templates before starting the service'
    fi
"
echo ""

# Step 8: Check nftables
echo "Step 8: Checking nftables"
ssh $SERVER "
    if sudo nft list set inet filter badipv4 >/dev/null 2>&1; then
        echo '✓ nftables set badipv4 exists'
        echo 'Currently blocked IPs:'
        sudo nft list set inet filter badipv4 | grep -c 'elements' || echo '0'
    else
        echo '⚠ WARNING: nftables set badipv4 does not exist'
    fi
"
echo ""

# Step 9: Start service (if config exists)
echo "Step 9: Starting service"
ssh $SERVER "
    if [ -f /usr/local/etc/badips.conf ]; then
        sudo systemctl enable bad_ips.service
        sudo systemctl start bad_ips.service
        sleep 2
        sudo systemctl status bad_ips.service
        echo ''
        echo '✓ Service started'
    else
        echo 'Skipping service start - no config file'
    fi
"
echo ""

# Step 10: Verify logs
echo "Step 10: Checking logs"
ssh $SERVER "
    echo 'Recent log entries:'
    sudo journalctl -u bad_ips.service --since '1 minute ago' -n 20 --no-pager
"
echo ""

echo "=========================================="
echo "✓ Installation test complete on $SERVER"
echo "=========================================="
echo ""
echo "To check status:"
echo "  ssh $SERVER 'sudo systemctl status bad_ips.service'"
echo ""
echo "To view logs:"
echo "  ssh $SERVER 'sudo journalctl -u bad_ips.service -f'"
echo ""
