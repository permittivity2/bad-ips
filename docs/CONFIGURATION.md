# Bad IPs Configuration Guide

## Overview

Bad IPs uses INI-style configuration files. The main config is `/usr/local/etc/badips.conf`, with detector-specific configs in `/usr/local/etc/badips.d/*.conf`.

## Main Configuration: badips.conf

### Required Settings

#### never_block_cidrs (REQUIRED)

**CRITICAL**: This parameter MUST be defined in your config file. It prevents accidentally blocking trusted networks.

```ini
[global]
never_block_cidrs = 23.116.91.65/29,10.0.0.0/8,192.168.1.0/24,127.0.0.0/8,0.0.0.0/8,224.0.0.0/4,240.0.0.0/4,169.254.0.0/16,172.16.0.0/12
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

### Hunter Mode (Default)

For servers that monitor local logs and block locally:

```ini
[global]
mode = hunter
blocking_time = 691200          # 8 days in seconds
sleep_time = 1                  # Seconds between log checks
heartbeat = 60                  # Heartbeat log interval
extra_time = 120                # Extra blocking time buffer
initial_journal_lookback = 86460  # 24 hours in seconds
never_block_cidrs = <YOUR_CIDRS_HERE>

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

### Gatherer Mode

For the central server that aggregates and propagates blocks:

```ini
[global]
mode = gatherer
blocking_time = 691200
never_block_cidrs = <YOUR_CIDRS_HERE>

# Gatherer-specific settings
propagation_delay = 5           # Seconds between propagation cycles
remote_server_timeout = 10      # SSH timeout in seconds
remote_server_timeout_action = log_only  # log_only, skip, or fail
remote_servers = proxy,mail,dovecot,ns01,ns02,ns03,nas

# Parallel operations
parallel_operations = 1         # Enable parallel SSH (1=yes, 0=no)
max_parallel_workers = 6        # Max concurrent SSH connections

# Database and nftables (same as hunter)
db_dir = /var/lib/bad_ips
db_file = /var/lib/bad_ips/bad_ips.sql
nft_table = inet
nft_family_table = filter
nft_set = badipv4
```

### Host-Specific Overrides

Override settings for specific hostnames:

```ini
[host:administrator]
mode = gatherer
remote_servers = proxy,mail,dovecot,ns01,ns02,ns03,nas

[host:proxy]
mode = hunter
```

## Detector Configuration: badips.d/*.conf

Detectors define which services to monitor and what patterns indicate attacks.

### Detector File Format

```ini
[detector:NAME]
units = systemd-unit1.service, systemd-unit2.service
pattern1 = First regex pattern to match
pattern2 = Second regex pattern to match
pattern3 = Third regex pattern to match
max_threshold = 5               # Max occurrences before blocking
time_window = 60                # Time window for threshold (seconds)
```

### Included Detectors

#### 10-sshd.conf

```ini
[detector:ssh]
units = ssh.service, sshd.service
pattern1 = Failed password for
pattern2 = Connection closed by authenticating user
pattern3 = Disconnected from authenticating user .* \[preauth\]
pattern4 = Connection reset by authenticating user
```

#### 20-postfix.conf

```ini
[detector:postfix]
units = postfix.service, postfix@-.service
pattern1 = SASL LOGIN authentication failed
pattern2 = lost connection after AUTH
pattern3 = too many errors after AUTH
pattern4 = disconnect from .* auth=0
```

#### 30-dovecot.conf

```ini
[detector:dovecot]
units = dovecot.service
pattern1 = auth failed
pattern2 = Disconnected \(auth failed
pattern3 = Aborted login
```

#### 40-nginx.conf

```ini
[detector:nginx]
units = nginx.service
pattern1 = 404.*GET.*wp-admin
pattern2 = 404.*GET.*wp-login
pattern3 = 404.*GET.*/\.env
pattern4 = 400 Bad Request
```

#### 70-bind.conf

```ini
[detector:named]
units = named.service, bind9.service
pattern1 = query \(cache\) '.*' denied
pattern2 = refused.*invalid zone
pattern3 = rate limit drop
```

### Creating Custom Detectors

Create a new file in `/usr/local/etc/badips.d/` (e.g., `90-custom.conf`):

```ini
[detector:myapp]
units = myapp.service
pattern1 = Authentication failure from ([0-9.]+)
pattern2 = Invalid login attempt
max_threshold = 3
time_window = 300
```

**Tips:**
- Use regex patterns to match log entries
- Capture groups `([0-9.]+)` will extract the IP address
- Lower numbered files (10-) are processed first
- Test patterns with: `journalctl -u myapp.service | grep "pattern"`

## SSH Configuration for Gatherer

The gatherer uses SSH to communicate with remote servers. SSH keys must be configured:

```bash
# On administrator (gatherer)
sudo -i
ssh-keygen -t ed25519 -C "root@administrator"

# Copy to each hunter server
for server in proxy mail dovecot ns01 ns02 ns03 nas; do
  ssh-copy-id gardner@$server
done
```

## Security Considerations

### never_block_cidrs is REQUIRED

- **NEVER** deploy without defining `never_block_cidrs`
- Always include your static IP addresses
- Include your entire management network
- Test blocking before deploying to production

### Blocking Time

- Default: 691,200 seconds (8 days)
- Adjust based on your threat model
- Longer times reduce database churn
- Shorter times allow faster recovery from false positives

### Propagation Delay

- Default: 5 seconds (gatherer only)
- Lower = faster propagation, higher CPU/network usage
- Higher = slower propagation, lower resource usage
- 5 seconds is a good balance for most networks

## Troubleshooting

### Check Configuration Loading

```bash
# Start in debug mode
sudo /usr/local/sbin/bad_ips --debug
```

### Verify never_block_cidrs

```bash
# Check loaded config
sudo grep never_block_cidrs /usr/local/etc/badips.conf
```

### Test IP Against CIDR

```bash
# Check if IP would be blocked
sudo /usr/local/sbin/bad_ips --test-ip 192.168.1.100
```

### Detector Not Firing

```bash
# Check systemd journal for patterns
sudo journalctl -u ssh.service | grep "Failed password"

# Verify detector config
cat /usr/local/etc/badips.d/10-sshd.conf

# Check bad_ips logs
sudo journalctl -u bad_ips.service -f
```

## Examples

### Hunter Configuration (mail server)

```ini
[global]
mode = hunter
blocking_time = 691200
never_block_cidrs = 23.116.91.65/29,10.0.0.0/8,192.168.1.0/24,127.0.0.0/8
db_dir = /var/lib/bad_ips
db_file = /var/lib/bad_ips/bad_ips.sql
nft_table = inet
nft_family_table = filter
nft_set = badipv4
log_level = INFO
```

### Gatherer Configuration (administrator)

```ini
[global]
mode = gatherer
blocking_time = 691200
never_block_cidrs = 23.116.91.65/29,10.0.0.0/8,192.168.1.0/24,127.0.0.0/8
propagation_delay = 5
remote_server_timeout = 10
remote_server_timeout_action = log_only
remote_servers = proxy,mail,dovecot,ns01,ns02,ns03,nas
parallel_operations = 1
max_parallel_workers = 6
db_dir = /var/lib/bad_ips
db_file = /var/lib/bad_ips/bad_ips.sql
nft_table = inet
nft_family_table = filter
nft_set = badipv4
log_level = INFO
```

## See Also

- README.md - Installation and overview
- DEBIAN.md - Building .deb packages
- nftables documentation: https://wiki.nftables.org/
- systemd.journal documentation: `man systemd.journal-fields`
