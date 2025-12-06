# Bad IPs - Distributed IP Blocking System

Version 1.0.0

## Overview

Bad IPs is a distributed hunter-gatherer architecture for blocking malicious IP addresses across a homelab infrastructure. It uses nftables for blocking, SQLite for tracking, and SSH-based propagation for correlation across multiple servers.

## Architecture

- **Hunter Mode**: Monitors local logs, blocks locally, exposes blocks for gathering
- **Gatherer Mode**: Polls remote servers, aggregates blocks, propagates to all servers

### Infrastructure

- 7 Hunter Servers: proxy, mail, dovecot, ns01, ns02, ns03, nas
- 1 Gatherer Server: administrator

## Features

- Real-time log monitoring with systemd journal integration
- Automatic IP blocking using nftables
- Configurable blocking duration (default: 8 days)
- Distributed correlation: IPs blocked on any server are blocked on all servers
- Per-service attack pattern detection (SSH, Postfix, Dovecot, Nginx, BIND, NFS, SMB)
- Never-block CIDR filtering for trusted networks
- SQLite database for persistence across reboots
- Parallel SSH operations for efficient propagation

## Installation

### Prerequisites

- Debian/Ubuntu Linux
- Perl 5.x
- nftables
- SQLite3

### From .deb Package

```bash
sudo dpkg -i bad-ips_1.0.0_all.deb
sudo apt-get install -f  # Install dependencies
```

### Configuration

#### Hunter Mode (default)

Edit `/usr/local/etc/badips.conf`:

```ini
[global]
mode = hunter
blocking_time = 691200
never_block_cidrs = 10.0.0.0/8,192.168.0.0/16
```

#### Gatherer Mode

```ini
[global]
mode = gatherer
propagation_delay = 5
remote_servers = proxy,mail,dovecot,ns01,ns02,ns03,nas
```

### Service Management

```bash
# Enable and start
sudo systemctl enable bad_ips.service
sudo systemctl start bad_ips.service

# Check status
sudo systemctl status bad_ips.service

# View logs
sudo journalctl -u bad_ips.service -f
```

## Detector Configuration

Detectors are configured in `/usr/local/etc/badips.d/*.conf`:

- `10-sshd.conf` - SSH brute force detection
- `20-postfix.conf` - Mail server attacks
- `30-dovecot.conf` - IMAP/POP3 attacks
- `40-nginx.conf` - Web server attacks
- `50-apache.conf` - Apache attacks
- `70-bind.conf` - DNS attacks

## Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd bad_ips

# Build .deb package
make deb

# Install
sudo dpkg -i bad-ips_1.0.0_all.deb
```

## Database

Bad IPs uses SQLite at `/var/lib/bad_ips/bad_ips.sql` to track:

- Blocked IPs
- First/last jail timestamps
- Expiration times
- Jail count (for repeat offenders)

## Nftables Integration

Bad IPs creates and manages the `badipv4` set in the `inet filter` table:

```bash
# View blocked IPs
sudo nft list set inet filter badipv4

# Manual block (not recommended)
sudo nft add element inet filter badipv4 { 1.2.3.4 timeout 691200s }

# Manual unblock
sudo nft delete element inet filter badipv4 { 1.2.3.4 }
```

## Troubleshooting

### Check if service is running

```bash
sudo systemctl status bad_ips.service
```

### View real-time logs

```bash
sudo journalctl -u bad_ips.service -f
```

### Check nftables set

```bash
sudo nft list set inet filter badipv4
```

### Verify database

```bash
sudo sqlite3 /var/lib/bad_ips/bad_ips.sql "SELECT COUNT(*) FROM jailed_ips;"
```

## License

Copyright (c) 2024 Gardner Homelab
All rights reserved.

## Author

Gardner <gardner@homelab>
