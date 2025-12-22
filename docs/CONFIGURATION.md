# Bad IPs Configuration Guide

## Overview

Bad IPs uses INI-style configuration files. The main config is `/usr/local/etc/badips.conf`, with detector-specific configs in `/usr/local/etc/badips.d/*.conf`.

## Main Configuration: badips.conf

### Quick Start

Copy the template and edit it:

```bash
sudo cp /usr/local/etc/badips.conf.template /usr/local/etc/badips.conf
sudo nano /usr/local/etc/badips.conf
```

### Required Settings

#### never_block_cidrs (REQUIRED)

**CRITICAL**: This parameter MUST be defined in your config file. It prevents accidentally blocking trusted networks.

```ini
[global]
never_block_cidrs = 10.0.0.0/8,192.168.1.0/24,127.0.0.0/8,0.0.0.0/8,224.0.0.0/4,240.0.0.0/4,169.254.0.0/16,172.16.0.0/12
```

**Common CIDRs to include:**
- `127.0.0.0/8` - Localhost
- `10.0.0.0/8` - Private network (Class A)
- `172.16.0.0/12` - Private network (Class B)
- `192.168.0.0/16` - Private network (Class C)
- `169.254.0.0/16` - Link-local addresses
- `224.0.0.0/4` - Multicast
- `240.0.0.0/4` - Reserved/experimental
- `0.0.0.0/8` - This network
- **YOUR PUBLIC IPS** - Add your static IPs/ranges here!

### Core Settings

```ini
[global]
# Network filtering (REQUIRED)
never_block_cidrs = 10.0.0.0/8,192.168.1.0/24,127.0.0.0/8

# Blocking duration
block_duration = 691200          # 8 days in seconds

# Automatic detection of services
auto_mode = 1                    # Automatically detect journal units and log files

# Performance settings
sleep_time = 2                   # Seconds between log checks
initial_journal_lookback = 86400 # How far back to check journal on startup (24 hours)
cleanup_every_seconds = 3600     # Cleanup interval

# Database settings
db_dir = /var/lib/bad_ips
db_file = /var/lib/bad_ips/bad_ips.sql

# Nftables settings
nft_table = inet
nft_family_table = filter
nft_set = badipv4

# Logging
log_level = INFO
```

### Optional Settings

#### always_block_cidrs
Block these networks permanently (in addition to detected IPs):

```ini
[global]
always_block_cidrs = 224.0.0.0/4,240.0.0.0/4
```

#### IPv6 Settings

```ini
[global]
never_block_cidrs_v6 = ::1/128,fe80::/10,fc00::/7,ff00::/8,::/128,2001:db8::/32
always_block_cidrs_v6 =
```

**Common IPv6 ranges to include:**
- `::1/128` - IPv6 localhost
- `fe80::/10` - Link-local addresses
- `fc00::/7` - Unique local addresses (private networks)
- `ff00::/8` - Multicast
- `::/128` - Unspecified address
- `2001:db8::/32` - Documentation/example addresses
- **YOUR PUBLIC IPv6s** - Add your static IPv6 addresses/ranges here!

#### Public Blocklist Plugins

Add external blocklists to supplement local detection:

```ini
[PublicBlocklistPlugins:Spamhaus]
urls = https://www.spamhaus.org/drop/drop.txt, https://www.spamhaus.org/drop/edrop.txt
fetch_interval = 3600
use_cache = 1
cache_path = /var/cache/badips/
active = 1

[PublicBlocklistPlugins:Feodotracker]
urls = https://feodotracker.abuse.ch/downloads/ipblocklist.txt
fetch_interval = 7200
use_cache = 1
cache_path = /var/cache/badips/
active = 0
```

### Host-Specific Overrides

Override settings for specific hostnames:

```ini
[host:webserver01]
log_level = DEBUG

[host:mailserver]
block_duration = 1209600  # 14 days
```

## Detector Configuration: badips.d/*.conf

Detectors define which services to monitor and what patterns indicate bad behavior.

### File Format

```ini
[global]
journal_units = <systemd-units>  # Comma-separated
file_sources = <log-files>       # Comma-separated
bad_conn_patterns = <regex>      # Perl regex, one per line
```

### Example: SSH Detector (10-sshd.conf)

```ini
[global]
journal_units = ssh.service,sshd.service
bad_conn_patterns =
    Failed password for .* from (\S+)
    Connection closed by authenticating user .* (\S+) port \d+ \[preauth\]
    Invalid user .* from (\S+)
    Unable to negotiate .* from (\S+)
```

### Example: Postfix Detector (20-postfix.conf)

```ini
[global]
journal_units = postfix.service,postfix@-.service
bad_conn_patterns =
    SASL LOGIN authentication failed.*\[(\S+)\]
    lost connection after AUTH from.*\[(\S+)\]
    too many errors after AUTH from.*\[(\S+)\]
```

### Example: Nginx Detector (40-nginx.conf)

```ini
[global]
file_sources = /var/log/nginx/access.log,/var/log/nginx/error.log
bad_conn_patterns =
    "(?:GET|POST) .* HTTP/\d\.\d" 40[0134] \d+ ".+" ".+" (\S+)
    limiting requests, excess:.* client: (\S+)
    limiting connections by zone.*client: (\S+)
```

### Available Detectors

Pre-configured detectors are installed in `/usr/local/etc/badips.d/`:
- `10-sshd.conf` - SSH brute force detection
- `20-postfix.conf` - Mail authentication failures
- `30-dovecot.conf` - IMAP/POP3 authentication
- `40-nginx.conf` - Web server abuse
- `50-apache.conf` - Apache web server
- `70-bind.conf` - DNS query abuse

## Database Configuration: badips.d/database.conf

Configure PostgreSQL connection (automatically created during install):

```ini
[global]
db_host = localhost
db_port = 5432
db_name = bad_ips
db_user = bad_ips
db_password = <your-password>
db_ssl_mode = disable
```

## Advanced Configuration

### Blocking Time Settings

```ini
[global]
# How long to block detected IPs (seconds)
block_duration = 691200  # 8 days

# Database batch settings
central_db_batch_size = 20
central_db_queue_timeout = 5
```

### Performance Tuning

```ini
[global]
# How often to check logs
sleep_time = 2

# Initial journal lookback on startup
initial_journal_lookback = 86400  # 24 hours

# Cleanup frequency
cleanup_every_seconds = 3600

# Max lines to tail from log files
max_file_tail_lines = 2000
```

### Nftables Configuration

```ini
[global]
# Table and set names
nft_table = inet
nft_family_table = filter
nft_set = badipv4

# IPv6 support
nft_set_v6 = badipv6
```

## Complete Example Configuration

```ini
[global]
# Required: Never block these networks
never_block_cidrs = 10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,127.0.0.0/8,169.254.0.0/16,224.0.0.0/4,240.0.0.0/4

# Blocking
block_duration = 691200
auto_mode = 1

# Performance
sleep_time = 2
initial_journal_lookback = 86400
cleanup_every_seconds = 3600

# Database
db_dir = /var/lib/bad_ips
db_file = /var/lib/bad_ips/bad_ips.sql

# Nftables
nft_table = inet
nft_family_table = filter
nft_set = badipv4

# Logging
log_level = INFO

# Public blocklists
[PublicBlocklistPlugins:Spamhaus]
urls = https://www.spamhaus.org/drop/drop.txt, https://www.spamhaus.org/drop/edrop.txt
fetch_interval = 3600
use_cache = 1
cache_path = /var/cache/badips/
active = 1
```

## Testing Configuration

After editing your config:

```bash
# Validate config syntax
sudo bad_ips --dry-run

# Restart service
sudo systemctl restart bad_ips.service

# Check status
sudo systemctl status bad_ips.service

# Watch logs
sudo journalctl -u bad_ips.service -f
```

## See Also

- README.md - Installation and overview
- DEBIAN.md - Building .deb packages
- nftables documentation: https://wiki.nftables.org/
- systemd.journal documentation: `man systemd.journal-fields`
