# 🛡️ Bad IPs - Distributed IP Blocking System

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/permittivity2/bad-ips/releases)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-orange.svg)](https://projects.thedude.vip/bad-ips/)

**A distributed hunter-gatherer architecture for blocking malicious IP addresses across your infrastructure.**

> 🚧 **ALPHA SOFTWARE** - This software is in early alpha testing. Use at your own risk and always test in non-production environments first.

---

## 🚀 Quick Start

Install Bad IPs on Ubuntu/Debian with a single command:

```bash
curl -fsSL https://projects.thedude.vip/bad-ips/install.sh | sudo bash
```

The installer will:
- ✅ Add the Silver Linings, LLC apt repository
- ✅ Install Bad IPs and all dependencies
- ✅ Guide you through configuration
- ✅ Start the service automatically

**Documentation**: https://projects.thedude.vip/bad-ips/

---

## 📖 Overview

Bad IPs uses a **hunter-gatherer architecture** to provide distributed IP blocking across multiple servers:

- **🎯 Hunters** monitor local logs, detect attacks, and block malicious IPs using nftables
- **🌐 Gatherers** collect blocked IPs from all hunters and propagate them across your entire infrastructure

### The NAFTA Effect

> *"An attack on one is an attack on all."*

When any server blocks an IP, that IP is automatically blocked on **all servers** in your infrastructure. An attacker trying to brute force SSH on your mail server will be instantly blocked on your web servers, DNS servers, and everything else.

---

## ✨ Features

### Core Features
- 🔍 **Real-time log monitoring** via systemd journal integration
- 🚫 **Automatic IP blocking** using nftables with configurable timeouts
- 🌐 **Distributed correlation** - blocks propagate across all servers
- 🔒 **Never-block CIDR filtering** to protect your trusted networks
- 💾 **SQLite database** for persistence across reboots
- ⚡ **Parallel SSH operations** for efficient propagation

### Supported Services
Out-of-the-box detection for:
- **SSH** (sshd) - Brute force attacks
- **Postfix** - Mail server attacks
- **Dovecot** - IMAP/POP3 attacks
- **Nginx** - Web server attacks
- **Apache** - Web server attacks
- **BIND** - DNS attacks
- **NFS** - Network file system attacks
- **Samba** - Windows file sharing attacks

---

## 🏗️ Architecture

Bad IPs uses a simple two-tier architecture:

```
┌─────────────────────────────────────┐
│  Gatherer (Administrator Server)   │
│  - Collects blocks from all hunters│
│  - Aggregates into master list     │
│  - Propagates to all servers       │
└─────────────────────────────────────┘
              │
              │ SSH (polls every 5s)
              ↓
    ┌─────────┬─────────┬─────────┐
    │ Hunter  │ Hunter  │ Hunter  │
    │ (proxy) │ (mail)  │ (ns01)  │
    │         │         │         │
    │ - Logs  │ - Logs  │ - Logs  │
    │ - Block │ - Block │ - Block │
    │ - nft   │ - nft   │ - nft   │
    └─────────┴─────────┴─────────┘
```

### Hunter Mode
- Monitors local systemd journal for attack patterns
- Blocks IPs locally using nftables
- Exposes blocked IPs for gathering
- Default blocking time: 8 days

### Gatherer Mode
- Polls all hunter servers via SSH
- Aggregates blocked IPs from all sources
- Propagates master block list to all hunters
- Filters trusted networks (never_block_cidrs)

---

## 📦 Installation

### Method 1: One-Line Installer (Recommended)

```bash
curl -fsSL https://projects.thedude.vip/bad-ips/install.sh | sudo bash
```

The installer will prompt you to choose:
1. **Hunter Mode** - For most servers (web, mail, DNS, etc.)
2. **Gatherer Mode** - For your central management server (usually one)

### Method 2: Apt Repository

```bash
# Add GPG key
curl -fsSL https://projects.thedude.vip/apt/silver-linings.gpg.key | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/silver-linings.gpg

# Add repository
echo "deb [signed-by=/etc/apt/trusted.gpg.d/silver-linings.gpg] https://projects.thedude.vip/apt/ ./" | sudo tee /etc/apt/sources.list.d/badips.list

# Update and install
sudo apt update
sudo apt install bad-ips
```

### Method 3: From Source

```bash
# Clone the repository
git clone https://github.com/permittivity2/bad-ips.git
cd bad-ips

# Build .deb package
make deb

# Install
sudo dpkg -i bad-ips_1.0.0_all.deb
sudo apt-get install -f  # Install dependencies
```

---

## ⚙️ Configuration

### Prerequisites

- **OS**: Debian 11+ or Ubuntu 20.04+
- **Perl**: 5.x (usually pre-installed)
- **nftables**: For IP blocking
- **SQLite3**: For database
- **SSH**: For gatherer mode communication

### Hunter Mode Configuration

Edit `/usr/local/etc/badips.conf`:

```ini
[global]
mode = hunter
blocking_time = 691200      # 8 days in seconds
sleep_time = 1              # Check logs every second
heartbeat = 60              # Log heartbeat every 60 seconds
never_block_cidrs = 10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,127.0.0.0/8

# Database
db_dir = /var/lib/bad_ips
db_file = /var/lib/bad_ips/bad_ips.sql
```

⚠️ **CRITICAL**: Always set `never_block_cidrs` to include your trusted networks and management IPs to avoid locking yourself out!

### Gatherer Mode Configuration

Edit `/usr/local/etc/badips.conf`:

```ini
[global]
mode = gatherer
propagation_delay = 5       # Seconds between propagation cycles
remote_servers = proxy,mail,dovecot,ns01,ns02,ns03,nas
never_block_cidrs = 10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,127.0.0.0/8

# SSH configuration
remote_server_timeout = 10
parallel_operations = 1
max_parallel_workers = 6
```

**Setup SSH keys** for passwordless access:

```bash
# On gatherer server (as root)
ssh-keygen -t ed25519
for server in proxy mail dovecot ns01 ns02 ns03 nas; do
    ssh-copy-id $server
done
```

### Detector Configuration

Detectors define attack patterns for each service. They live in `/usr/local/etc/badips.d/`:

```
10-sshd.conf       # SSH brute force
20-postfix.conf    # Mail server attacks
30-dovecot.conf    # IMAP/POP3 attacks
40-nginx.conf      # Nginx attacks
50-apache.conf     # Apache attacks
70-bind.conf       # DNS attacks
80-nas.conf        # NFS/SMB attacks
```

Example detector (`/usr/local/etc/badips.d/10-sshd.conf`):

```ini
[detector:sshd]
enabled = 1
units = sshd.service
pattern1 = Failed password for invalid user
pattern2 = Failed password for root
pattern3 = Failed password for .* from
pattern4 = Connection closed by authenticating user .* port [0-9]+ \[preauth\]
pattern5 = Disconnected from authenticating user .* port [0-9]+ \[preauth\]
```

---

## 🔧 Usage

### Service Management

```bash
# Start the service
sudo systemctl start bad_ips.service

# Enable on boot
sudo systemctl enable bad_ips.service

# Check status
sudo systemctl status bad_ips.service

# View logs
sudo journalctl -u bad_ips.service -f

# Restart after config changes
sudo systemctl restart bad_ips.service
```

### Manual Operations

```bash
# View blocked IPs
sudo nft list set inet filter badipv4

# Count blocked IPs
sudo nft list set inet filter badipv4 | grep -o "," | wc -l

# Check database
sudo sqlite3 /var/lib/bad_ips/bad_ips.sql "SELECT COUNT(*) FROM jailed_ips;"

# View recently blocked IPs
sudo sqlite3 /var/lib/bad_ips/bad_ips.sql "SELECT ip, first_jailed_at, expires_at FROM jailed_ips ORDER BY first_jailed_at DESC LIMIT 10;"

# Manually unblock an IP
sudo nft delete element inet filter badipv4 { 1.2.3.4 }
sudo sqlite3 /var/lib/bad_ips/bad_ips.sql "DELETE FROM jailed_ips WHERE ip='1.2.3.4';"
```

---

## 🗄️ Database Schema

Bad IPs uses SQLite at `/var/lib/bad_ips/bad_ips.sql`:

```sql
CREATE TABLE jailed_ips (
    ip TEXT PRIMARY KEY,
    first_jailed_at INTEGER,
    last_jailed_at INTEGER,
    expires_at INTEGER,
    jail_count INTEGER DEFAULT 1
);
```

---

## 🔥 Nftables Integration

Bad IPs creates the `badipv4` set in the `inet filter` table with timeout support:

```bash
# The set is created automatically:
nft add set inet filter badipv4 { type ipv4_addr ; flags timeout ; }

# Drop rule is added automatically:
nft add rule inet filter input ip saddr @badipv4 drop
```

IPs are added with automatic expiration:

```bash
nft add element inet filter badipv4 { 1.2.3.4 timeout 691200s }
```

---

## 🛠️ Troubleshooting

### Service Won't Start

```bash
# Check logs for errors
sudo journalctl -u bad_ips.service -n 50

# Verify config syntax
perl -c /usr/local/sbin/bad_ips

# Check if nftables table exists
sudo nft list tables
```

### Not Blocking IPs

```bash
# Verify detectors are enabled
grep "enabled = 1" /usr/local/etc/badips.d/*.conf

# Check if logs are being monitored
sudo journalctl -u sshd.service -f  # Should see login attempts

# Verify nftables set exists
sudo nft list set inet filter badipv4
```

### Gatherer Not Propagating

```bash
# Test SSH connectivity
ssh proxy "echo success"

# Check gatherer logs
sudo journalctl -u bad_ips.service | grep gatherer

# Verify remote_servers list
grep remote_servers /usr/local/etc/badips.conf
```

### Locked Yourself Out?

**Prevention**: Always configure `never_block_cidrs` before starting!

**Recovery** (requires console/IPMI access):

```bash
# Stop the service
sudo systemctl stop bad_ips.service

# Clear all blocks
sudo nft flush set inet filter badipv4

# Clear database
sudo sqlite3 /var/lib/bad_ips/bad_ips.sql "DELETE FROM jailed_ips;"

# Fix your never_block_cidrs config
sudo nano /usr/local/etc/badips.conf

# Restart
sudo systemctl start bad_ips.service
```

---

## 🚀 Roadmap

### Phase 9: Reporting System *(In Development)*
- Per-hunter statistics
- Aggregate reporting across infrastructure
- Whois lookups with CIDR caching
- Country-based analysis of attacks
- Trend analysis and visualization
- Multiple export formats (text, JSON, CSV, HTML)

### Phase 10: AI-Powered Review *(Planned)*
- AI analysis of blocked IPs before propagation
- False positive detection via pattern analysis
- Multi-source reputation scoring (AbuseIPDB, Shodan, etc.)
- Confidence intervals for automated decision-making
- Automatic unblock suggestions for misidentified IPs

### Future Enhancements
- **Alarming**: Threshold-based alerts via email/SMS/webhook
- **Web Dashboard**: Real-time monitoring and management UI
- **API**: RESTful API for integration with other tools
- **IPv6 Support**: Extend blocking to IPv6 addresses
- **Cloud Integration**: Support for AWS, GCP, Azure security groups

---

## 📚 Documentation

- **Website**: https://projects.thedude.vip/bad-ips/
- **Installation Guide**: https://projects.thedude.vip/bad-ips/install.sh
- **Configuration Reference**: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
- **Phase 8-10 Design**: [docs/PHASE_8_9_DESIGN.md](docs/PHASE_8_9_DESIGN.md)

---

## 🤝 Contributing

This is currently an alpha project. Bug reports and feature requests are welcome!

**Report Issues**: https://github.com/permittivity2/bad-ips/issues

---

## 📄 License

Copyright (c) 2025 **Silver Linings, LLC**
All rights reserved.

This software is currently proprietary. Licensing terms TBD.

---

## 👤 Author

**Silver Linings, LLC**
Contact: gardner@thedude.vip
Website: https://projects.thedude.vip/

---

## 🙏 Acknowledgments

Bad IPs was inspired by [fail2ban](https://www.fail2ban.org/) but reimagined with:
- Distributed architecture for multi-server correlation
- Perl for superior regex performance and string manipulation
- Native nftables integration for modern Linux systems
- SQLite for simplicity and reliability

---

## ⚠️ Security Notice

- **Never run Bad IPs without configuring `never_block_cidrs`** - you may lock yourself out
- **Always have console/IPMI access** to your servers as a backup
- **Test in non-production environments first** - this is alpha software
- **Monitor logs regularly** during initial deployment to catch false positives
- **Use strong SSH key authentication** for gatherer mode communication

---

**Made with ❤️ by Silver Linings, LLC**
