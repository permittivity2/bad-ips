# Bad IPs Configuration Guide

## Overview

Bad IPs uses INI-style configuration files. The main config is `/usr/local/etc/badips.conf`, with detector-specific configs in `/usr/local/etc/badips.d/*.conf`.

## Role Mode (4.0)

A `role` in `[global]` selects the 4.0 engine; `man bad_ips` (ROLE MODE) is
the authoritative reference. A minimal report host:

```ini
[global]
role = report
never_block_cidrs = 203.0.113.0/29, 2001:db8::/64
db_host = db.example.net
db_port = 6432
db_name = homelab
db_user = badips_runtime
db_password = ...
db_schema = badips
```

and the block host (the edge) adds `role = block` and
`block_interfaces = eth6, eth7`. Rules are `[rule:NAME]` sections (shipped in
`badips.d/60-rules.conf`); redefine a section with the same name in a later
file to change it, or set `active = 0` there to switch it off. The private,
loopback, link-local and multicast ranges are always never-blocked.

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
blocking_time = 691200           # TTL for blocked IPs in nftables

# Database synchronization control
sync_blocked_to_database = 0     # Report local blocks to database (0=no, 1=yes)
block_ips_from_database = 0      # Pull blocks from database (0=no, 1=yes)

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
nft_family_table = badips
nft_set = badipv4

# Logging
log_level = INFO
```

### nftables Configuration

Bad IPs uses its own isolated nftables table with dedicated sets for blocking:

```ini
[global]
# nftables table family (address family type)
nft_table = inet              # Use 'inet' for dual-stack (IPv4 and IPv6)

# nftables table name
nft_family_table = badips     # The table created at /etc/nftables.d/99-badips.nft

# Primary IPv4 set name (IPv6 equivalent is auto-suffixed with _v6)
nft_set = badipv4             # IPv6 set is automatically badipv6
```

**How it works:**
- Bad IPs creates a dedicated `table inet badips` at `/etc/nftables.d/99-badips.nft`
- This table is completely separate from your main firewall (`inet filter`)
- The table contains 6 sets:
  - `badipv4` and `badipv6` - Dynamic IP blocks with automatic timeout
  - `never_block` and `never_block_v6` - Trusted networks (never blocked)
  - `always_block` and `always_block_v6` - Permanently blocked IPs
- The table uses the `prerouting` hook at priority `-150`
- This means Bad IPs processes traffic **before** your main firewall rules

**Firewall Compatibility:**
- Works seamlessly with UFW, firewalld, and custom nftables rules
- No configuration conflicts - each firewall operates independently
- Bad IPs runs first and drops malicious traffic early, reducing processing overhead

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

Each file declares a plugin instance as its section header, followed by that
plugin's keys:

```ini
[Plugins:<PluginName>]
active = 1                       # 1 to enable this instance
name = <display name>            # used in logs and database records
journal_unit = <systemd-units>   # comma-separated
log_paths = <log-files>          # comma-separated
monitor_method = auto            # journald | files | both | auto
```

Detection patterns use the form `Short Description:::Regex`. The description
appears in the logs; the regex is matched against each log line.

### Pattern kinds

`GeneralLogMonitor` recognises two kinds of pattern, and the distinction
matters:

| Key | Meaning |
|---|---|
| `bad_login_pattern_NN` | Evidence of an attack. Counts toward a block. |
| `good_login_pattern_NN` | Evidence a real user authenticated. Tested **first** and wins outright. |

When a good pattern matches, that address is exempt from blocking for
`good_login_grace` seconds and any failure tally against it is discarded.
Without good patterns the daemon has no concept of a legitimate user, and a
successful login followed moments later by a harmless pre-auth disconnect is
enough to lock the real user out.

**Do not match ordinary disconnects.** A bare `Connection closed by <ip>
[preauth]` or `Connection reset by <ip> [preauth]` is written any time a
client drops the connection during the handshake — connection sharing, an
editor's remote plugin, or a flaky mobile link all produce it. Prefer the
`Connection closed by authenticating user` variant, which names a username
and so reflects a real authentication attempt.

### Thresholds

| Key | Default | Meaning |
|---|---|---|
| `block_after_n_attempts` | `1` | Bad-pattern matches from one address needed to block it. |
| `attempt_window` | `600` | Seconds over which those matches are counted. |
| `good_login_grace` | `3600` | Seconds a successful login protects an address. |

`block_after_n_attempts` is honoured as of **3.8.0**. Earlier releases parsed
the key but never acted on it, so every single match blocked immediately.

A per-plugin `block_duration` is **not** implemented — block length comes from
the global `blocking_time` in `badips.conf`.

### Example: SSH Detector (10-sshd.conf)

```ini
[Plugins:GeneralLogMonitor]
active = 1
name = SSH
log_paths = /var/log/auth.log, /var/log/secure
journal_unit = ssh.service, sshd.service
monitor_method = auto
initial_fetch = 7200
fetch_interval = 2

# Evidence a real user got in
good_login_pattern_01 = Accepted publickey:::Accepted publickey for .* from
good_login_pattern_02 = Accepted password:::Accepted password for .* from
good_login_grace = 3600

# Evidence of an attack
bad_login_pattern_01 = Failed password:::Failed password for .* from
bad_login_pattern_02 = Invalid user:::Invalid user .* from
bad_login_pattern_03 = Authentication Failure:::pam_unix\(sshd:auth\): authentication failure
bad_login_pattern_04 = Preauth close after auth attempt:::Connection closed by authenticating user \S+ .* \[preauth\]

block_after_n_attempts = 3
attempt_window = 600
```

Note the escaped parentheses in `pam_unix\(sshd:auth\)`. Unescaped, the
parentheses form a regex capture group and the pattern silently never matches
a real PAM log line.

> The Postfix and Nginx examples below still describe an older
> `[global] bad_conn_patterns` layout and have not been brought in line with
> the shipped config files.

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

### Database Synchronization Control

Control how this server interacts with the central database. This enables deployment modes including honeypot servers and one-way data sharing.

```ini
[global]
# sync_blocked_to_database: Report locally detected blocks to central database
#   0 = disabled (honeypot mode - detects but doesn't report)
#   1 = enabled (default for production servers)
sync_blocked_to_database = 0

# block_ips_from_database: Pull and block IPs detected by other servers
#   0 = disabled (honeypot mode - independent blocking)
#   1 = enabled (default for production servers)
block_ips_from_database = 0
```

**Deployment Modes:**

- **Honeypot Mode** (both = 0): Detects and blocks threats locally but operates independently. Perfect for test/staging environments or isolated honeypots.
- **Push-Only Mode** (sync=1, block=0): Reports threats to database but doesn't pull from other servers. Useful for edge servers that contribute data without trust in other sources.
- **Pull-Only Mode** (sync=0, block=1): Leverages collective intelligence but doesn't report own data. Useful for compliance or privacy-sensitive systems.
- **Full Sync Mode** (both = 1): Bidirectional synchronization. Standard production deployment with maximum visibility across all servers.

**Note:** The `central_db_sync` thread always runs regardless of `sync_blocked_to_database` setting to prevent queue memory leaks. When disabled, queued items are drained without being sent to the database.

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

### Honeypot Mode (Isolated Server)

```ini
[global]
# Required: Never block these networks
never_block_cidrs = 10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,127.0.0.0/8,169.254.0.0/16,224.0.0.0/4,240.0.0.0/4

# Blocking
block_duration = 691200
blocking_time = 691200
auto_mode = 1

# Database synchronization (honeypot mode - no sync)
sync_blocked_to_database = 0
block_ips_from_database = 0

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

### Production Mode (Full Database Sync)

```ini
[global]
# Required: Never block these networks
never_block_cidrs = 10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,127.0.0.0/8,169.254.0.0/16,224.0.0.0/4,240.0.0.0/4

# Blocking
block_duration = 691200
blocking_time = 691200
auto_mode = 1

# Database synchronization (full sync)
sync_blocked_to_database = 1
block_ips_from_database = 1

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
