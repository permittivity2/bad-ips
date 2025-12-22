# Privilege Separation: Run Bad IPs as Non-Root User

## Executive Summary

Implement privilege separation by running the bad_ips daemon as a dedicated non-root user (`badips`) with limited sudo access to only the necessary nft commands for the `inet badips` table.

**Key Changes:**
- Create system user `badips` with no login shell and no home directory
- Update systemd service to run as `User=badips`
- Add sudoers rule allowing `badips` user to run specific nft commands without password
- Update file/directory ownership for `/var/lib/bad_ips` and `/var/log/bad_ips`
- Modify BadIPs::NFT module to execute nft commands via sudo

**Benefits:**
- **Security**: Daemon runs with minimal privileges (no root access except for nft)
- **Attack Surface Reduction**: Compromised daemon cannot modify system files
- **Principle of Least Privilege**: Only has access to nft operations on inet badips table
- **Audit Trail**: All nft operations appear in sudo logs

**Risk Assessment:**
- **Low risk**: Well-established pattern used by many daemons (nginx, apache, mysql)
- **Minimal complexity**: Just user creation + sudoers rule + service file change
- **Rollback**: Easy to revert to root if issues arise

## Current Implementation

### Execution Context
- **User**: `root` (defined in `/etc/systemd/system/bad_ips.service`)
- **nft Access**: Direct execution as root, no restrictions

### nft Commands Used (via BadIPs::NFT module)

1. **Block IP (runtime, frequent):**
   ```bash
   nft add element inet badips badipv4 { <ip> timeout <seconds>s }
   nft add element inet badips badipv6 { <ip> timeout <seconds>s }
   ```

2. **Flush static sets (startup/reload):**
   ```bash
   nft flush set inet badips never_block
   nft flush set inet badips never_block_v6
   nft flush set inet badips always_block
   nft flush set inet badips always_block_v6
   ```

3. **Add static CIDRs (startup/reload):**
   ```bash
   nft add element inet badips never_block { <cidr> }
   nft add element inet badips never_block_v6 { <cidr> }
   nft add element inet badips always_block { <cidr> }
   nft add element inet badips always_block_v6 { <cidr> }
   ```

4. **Read ruleset (startup, read-only):**
   ```bash
   nft -j list ruleset
   ```

### File/Directory Access Requirements

**Created by postinst, currently owned by root:**
- `/var/lib/bad_ips/` (mode 755) - State/database files
- `/var/log/bad_ips/` (mode 755) - Log directory
- `/var/log/bad_ips/bad_ips.log` (mode 640) - Log file

**Configuration files (remain root-owned, read by badips):**
- `/usr/local/etc/badips.conf` - Main config
- `/usr/local/etc/badips.d/` - Config directory
- `/usr/local/etc/badips/log4perl.conf` - Logging config
- `/etc/nftables.d/99-badips.nft` - nftables rules (not modified by daemon)

## Proposed Implementation

### 0. Username Configuration (NEW)

**Configuration File:** `/etc/default/bad_ips`

The service username will be configurable (default: `badips`) and stored in `/etc/default/bad_ips`:
```bash
# Bad IPs service user configuration
BADIPS_USER=badips
BADIPS_GROUP=badips
```

**Implementation:**
- `website/install.sh` prompts for username with default "badips"
- `DEBIAN/postinst` reads from `/etc/default/bad_ips` if exists, otherwise defaults to "badips"
- This allows custom usernames while maintaining "badips" as the sensible default

### 1. Create Service System User

**User Specifications:**
- Username: Configurable (default: `badips`)
- Type: System user (UID < 1000)
- Home: `/nonexistent` (no home directory)
- Shell: `/usr/sbin/nologin` (no interactive login)
- Primary Group: Matching username (e.g., `badips`)
- Supplementary Groups: `systemd-journal` (for journalctl), `adm` (for /var/log access)
- Purpose: Service account for bad_ips daemon

**Creation Method:**
```bash
# In website/install.sh - prompt for username
read -p "Service username [badips]: " BADIPS_USER
BADIPS_USER=${BADIPS_USER:-badips}

# Validate username
if ! [[ "$BADIPS_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    echo "Error: Invalid username format"
    exit 1
fi

# Save to configuration file
cat > /etc/default/bad_ips <<EOF
# Bad IPs service user configuration
BADIPS_USER=$BADIPS_USER
BADIPS_GROUP=$BADIPS_USER
EOF
chmod 644 /etc/default/bad_ips

# Create user if doesn't exist (install.sh can do this before package install)
if ! getent passwd "$BADIPS_USER" > /dev/null; then
    adduser --system --group --no-create-home \
        --home /nonexistent --shell /usr/sbin/nologin \
        "$BADIPS_USER"
    echo "Created system user: $BADIPS_USER"
fi

# Add to supplementary groups for log access
usermod -aG systemd-journal "$BADIPS_USER"
usermod -aG adm "$BADIPS_USER"
echo "Added $BADIPS_USER to systemd-journal and adm groups"
```

```bash
# In DEBIAN/postinst - read config and create user as fallback
# Load username from configuration (default to badips if not set)
if [ -f /etc/default/bad_ips ]; then
    . /etc/default/bad_ips
fi
BADIPS_USER=${BADIPS_USER:-badips}
BADIPS_GROUP=${BADIPS_GROUP:-badips}

# Create user if doesn't exist
if ! getent passwd "$BADIPS_USER" > /dev/null; then
    adduser --system --group --no-create-home \
        --home /nonexistent --shell /usr/sbin/nologin \
        "$BADIPS_USER"
    echo "Created system user: $BADIPS_USER"
fi

# Ensure user is in required groups
usermod -aG systemd-journal "$BADIPS_USER" 2>/dev/null || true
usermod -aG adm "$BADIPS_USER" 2>/dev/null || true
```

**Rationale:**
- `--system`: Creates system user (UID < 1000)
- `--group`: Creates matching group
- `--no-create-home`: No home directory needed
- `--home /nonexistent`: Standard for service accounts
- `--shell /usr/sbin/nologin`: Prevents interactive login
- `systemd-journal` group: Standard group for journalctl read access
- `adm` group: Standard group (Debian/Ubuntu) for /var/log read access

### 2. Configure sudoers Rule

**Sudoers File:** `/etc/sudoers.d/bad_ips` (mode 0440)

**Rule Specification:**
- User: Configurable (default: `badips`)
- NOPASSWD: Yes (required for automated operation)
- Scope: Limited to `inet badips` table only
- Commands: Only necessary nft operations

**Implementation in DEBIAN/postinst:**
```bash
# Load username from configuration
if [ -f /etc/default/bad_ips ]; then
    . /etc/default/bad_ips
fi
BADIPS_USER=${BADIPS_USER:-badips}

# Create sudoers file
cat > /etc/sudoers.d/bad_ips <<SUDOEOF
# Bad IPs sudoers configuration
# Allows $BADIPS_USER user to manage the inet badips nftables table
# Created by bad-ips package installation

# Command aliases for allowed nft operations
Cmnd_Alias NFT_BADIPS_ADD = /usr/sbin/nft add element inet badips badipv4 *
Cmnd_Alias NFT_BADIPS_ADD_V6 = /usr/sbin/nft add element inet badips badipv6 *
Cmnd_Alias NFT_BADIPS_FLUSH = /usr/sbin/nft flush set inet badips never_block*, \\
                              /usr/sbin/nft flush set inet badips always_block*
Cmnd_Alias NFT_BADIPS_LIST = /usr/sbin/nft -j list ruleset, \\
                             /usr/sbin/nft list ruleset

# Allow $BADIPS_USER user to run these commands without password
$BADIPS_USER ALL=(root) NOPASSWD: NFT_BADIPS_ADD, NFT_BADIPS_ADD_V6, NFT_BADIPS_FLUSH, NFT_BADIPS_LIST
SUDOEOF

# Set correct permissions
chmod 0440 /etc/sudoers.d/bad_ips

# Validate sudoers syntax
if ! visudo -c -f /etc/sudoers.d/bad_ips >/dev/null 2>&1; then
    echo "ERROR: Invalid sudoers syntax in /etc/sudoers.d/bad_ips"
    echo "Removing invalid file to prevent system issues"
    rm -f /etc/sudoers.d/bad_ips
    exit 1
fi

echo "Sudoers configuration created and validated"
```

**Rationale:**
- Command aliases improve readability and maintainability
- Wildcard `*` allows arguments but restricts to specific table/set
- `NOPASSWD` required since service accounts can't enter passwords
- Limited to read (list) and write (add element, flush set) on inet badips table only
- Cannot modify other tables or create/destroy tables

**Security Considerations:**
- ✅ Cannot modify firewall rules outside inet badips table
- ✅ Cannot create or destroy tables
- ✅ Cannot modify chains or policies
- ✅ Cannot run other system commands
- ⚠️ Could potentially add arbitrary IPs to badips sets (but that's the daemon's purpose)

### 3. Update systemd Service Configuration

**Base Service File:** `/etc/systemd/system/bad_ips.service` (remains mostly unchanged)

**NEW: SystemD Drop-in File:** `/etc/systemd/system/bad_ips.service.d/user.conf`

**Rationale for Drop-in Approach:**
- Base service file in the package remains generic
- Drop-in created dynamically by postinst with the configured username
- Cleaner upgrades (drop-in persists across package updates)
- Standard systemd best practice for runtime configuration

**Base Service File (minimal changes):**
```ini
[Unit]
Description=Bad IP Blocking Service
After=network.target nftables.service
Wants=nftables.service
ConditionPathExists=/etc/nftables.d/99-badips.nft

[Service]
Type=simple
ExecStart=/bin/sh -c 'tail -F /var/log/bad_ips/bad_ips.log | systemd-cat -t bad_ips & exec /usr/local/sbin/bad_ips'
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
TimeoutStopSec=330
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

**Drop-in File Created by DEBIAN/postinst:**
```bash
# Load username from configuration
if [ -f /etc/default/bad_ips ]; then
    . /etc/default/bad_ips
fi
BADIPS_USER=${BADIPS_USER:-badips}
BADIPS_GROUP=${BADIPS_GROUP:-badips}

# Create systemd drop-in directory
mkdir -p /etc/systemd/system/bad_ips.service.d

# Create user configuration drop-in
cat > /etc/systemd/system/bad_ips.service.d/user.conf <<SYSDEOF
[Service]
# Run as non-root user with limited privileges
User=$BADIPS_USER
Group=$BADIPS_GROUP

# Supplementary groups for log/journal access
SupplementaryGroups=systemd-journal adm
SYSDEOF

echo "Created systemd drop-in for user $BADIPS_USER"
```

**Key Changes:**
- Base service file remains generic (no hardcoded user)
- Drop-in file dynamically sets `User=`, `Group=`, and `SupplementaryGroups=`
- `SupplementaryGroups=` ensures access to journalctl and /var/log

### 4. Update BadIPs::NFT Module

**File:** `/usr/local/lib/site_perl/BadIPs/NFT.pm`

**Modify all nft command executions to use sudo:**

#### Current Implementation (lines 112-138):
```perl
my $cmd = "nft add element $self->{table} $self->{family_table} $set { $ip timeout ${ttl}s }";

if ($self->{dry_run}) {
    # ... dry run logic ...
}

my ($out, $rc);
eval {
    $out = qx($cmd 2>&1);  # Direct execution
    $rc  = $? >> 8;
};
```

#### New Implementation:
```perl
my $cmd = "sudo nft add element $self->{table} $self->{family_table} $set { $ip timeout ${ttl}s }";

if ($self->{dry_run}) {
    # ... dry run logic ...
}

my ($out, $rc);
eval {
    $out = qx($cmd 2>&1);  # Execute via sudo
    $rc  = $? >> 8;
};
```

**All locations to update:**

1. **block_ip()** (line ~112): Add `sudo` to `nft add element` command
2. **_refresh_set()** (line ~241): Add `sudo` to `nft flush set` command
3. **_refresh_set()** (line ~257): Add `sudo` to `nft add element` command
4. **ruleset_as_json()** (line ~205): Add `sudo` to `nft -j list ruleset` command

**Pattern:**
Replace all instances of:
- `"nft add element` → `"sudo nft add element`
- `"nft flush set` → `"sudo nft flush set`
- `` `nft -j list ruleset` `` → `` `sudo nft -j list ruleset` ``

### 5. Update File/Directory Ownership and Permissions

**In DEBIAN/postinst:**

```bash
# Load username from configuration
if [ -f /etc/default/bad_ips ]; then
    . /etc/default/bad_ips
fi
BADIPS_USER=${BADIPS_USER:-badips}
BADIPS_GROUP=${BADIPS_GROUP:-badips}

# Ensure service user owns necessary directories
chown -R $BADIPS_USER:$BADIPS_GROUP /var/lib/bad_ips
chown -R $BADIPS_USER:$BADIPS_GROUP /var/log/bad_ips

# Ensure correct permissions on directories
chmod 755 /var/lib/bad_ips
chmod 755 /var/log/bad_ips
chmod 640 /var/log/bad_ips/bad_ips.log 2>/dev/null || true

# CRITICAL: Secure configuration files (contain database passwords)
if [ -f /usr/local/etc/badips.conf ]; then
    chmod 640 /usr/local/etc/badips.conf
    chown root:$BADIPS_GROUP /usr/local/etc/badips.conf
fi

if [ -d /usr/local/etc/badips.d ]; then
    chmod 750 /usr/local/etc/badips.d
    chown root:$BADIPS_GROUP /usr/local/etc/badips.d
    # Secure all config files in the directory
    find /usr/local/etc/badips.d -type f -name "*.conf" -exec chmod 640 {} \;
    find /usr/local/etc/badips.d -type f -name "*.conf" -exec chown root:$BADIPS_GROUP {} \;
fi

echo "File ownership and permissions updated for user $BADIPS_USER"
```

**Rationale:**
- Service user must be able to write to state directory (`/var/lib/bad_ips`)
- Service user must be able to write to log directory (`/var/log/bad_ips`)
- **SECURITY**: Configuration files contain database passwords in plaintext
  - Mode 640 (owner read/write, group read-only, world no access)
  - Owner: root (prevents service user from modifying configs)
  - Group: $BADIPS_GROUP (allows service user to read configs)
  - This prevents privilege escalation while allowing necessary read access

## Implementation Steps

### Phase 1: Package and Installation Changes

1. **Update website/install.sh:**
   - Add username prompt with default "badips"
   - Add username validation
   - Create `/etc/default/bad_ips` configuration file
   - Create user before package installation
   - Add user to supplementary groups (systemd-journal, adm)

2. **Update DEBIAN/postinst:**
   - Read username from `/etc/default/bad_ips` (fallback to "badips")
   - Add user creation logic as fallback (with existence check)
   - Add user to supplementary groups (systemd-journal, adm)
   - Create and validate sudoers file dynamically
   - Create systemd drop-in file with User/Group configuration
   - Update directory ownership using configured username
   - Secure configuration file permissions (640, root:$BADIPS_GROUP)

3. **Update DEBIAN/postrm:**
   - Add user removal logic (on purge only)
   - Remove sudoers file
   - Remove systemd drop-in directory
   - Remove `/etc/default/bad_ips` on purge

4. **Update etc/systemd/system/bad_ips.service:**
   - REMOVE hardcoded `User=root` (if present)
   - Keep service file generic (User will be set by drop-in)
   - Fix TimeoutStopSec and RestartSec to match current values

5. **Update usr/local/lib/site_perl/BadIPs/NFT.pm:**
   - Prepend `sudo ` to all nft commands (4 locations)

### Phase 2: Testing

Test scenarios:

1. **Fresh installation:**
   - User created automatically
   - Service starts as badips user
   - Can block IPs successfully
   - Can read nftables ruleset
   - Can flush and refresh static sets

2. **Upgrade from root:**
   - User created if doesn't exist
   - Service restarts with new user
   - Existing state preserved
   - No permission errors

3. **Privilege verification:**
   - Daemon cannot write to /etc
   - Daemon cannot modify system files
   - Daemon can only run allowed nft commands
   - sudo logs show nft command executions

4. **Error scenarios:**
   - Missing sudoers file (daemon fails gracefully)
   - Incorrect sudoers permissions (sudo fails)
   - User doesn't exist (systemd fails to start)

### Phase 3: Documentation

Update documentation to reflect:
- Service runs as badips user
- sudo configuration for nft access
- Security implications
- Troubleshooting for permission issues

## Files to Modify

### 1. `website/install.sh` (NEW)
**Changes:**
- Add username prompt section (after database configuration)
- Prompt: "Service username [badips]: "
- Validate username format (alphanumeric, lowercase, underscore/hyphen)
- Create `/etc/default/bad_ips` with BADIPS_USER and BADIPS_GROUP
- Create user if doesn't exist
- Add user to supplementary groups: systemd-journal, adm
- Location: After database setup, before nftables configuration

### 2. `DEBIAN/postinst`
**Changes:**
- Read `/etc/default/bad_ips` to get username (fallback: "badips")
- Add user creation logic as fallback (with existence check)
- Add user to supplementary groups (systemd-journal, adm)
- Dynamically create `/etc/sudoers.d/bad_ips` with correct username
- Validate sudoers file with `visudo -c`
- Create systemd drop-in at `/etc/systemd/system/bad_ips.service.d/user.conf`
- Update directory ownership to $BADIPS_USER:$BADIPS_GROUP
- Secure config files: chmod 640, chown root:$BADIPS_GROUP

### 3. `DEBIAN/postrm`
**Changes:**
- Add user removal (on purge only): `deluser --system $BADIPS_USER`
- Remove `/etc/sudoers.d/bad_ips`
- Remove `/etc/systemd/system/bad_ips.service.d/` directory
- Remove `/etc/default/bad_ips` (on purge)

### 4. `etc/systemd/system/bad_ips.service`
**Changes:**
- REMOVE `User=root` line (line 13)
- User/Group will be set via drop-in file
- Service file remains generic for cleaner package upgrades

### 5. `usr/local/lib/site_perl/BadIPs/NFT.pm`
**Changes:**
- Line ~112: `nft add element` → `sudo nft add element`
- Line ~205: `nft -j list ruleset` → `sudo nft -j list ruleset`
- Line ~241: `nft flush set` → `sudo nft flush set`
- Line ~257: `nft add element` → `sudo nft add element`

### 6. `/etc/default/bad_ips` (NEW FILE - created by install.sh)
**Content:**
```bash
# Bad IPs service user configuration
BADIPS_USER=badips
BADIPS_GROUP=badips
```

### 7. `/etc/sudoers.d/bad_ips` (NEW FILE - created by postinst)
**Content:**
- Dynamically generated with configured username
- Command aliases for allowed nft operations
- Mode 0440, validated with visudo

### 8. `/etc/systemd/system/bad_ips.service.d/user.conf` (NEW FILE - created by postinst)
**Content:**
- Dynamically generated with configured username
- Sets User=, Group=, and SupplementaryGroups=

## Security Analysis

### Attack Surface Reduction

**Before (root):**
- Full system access
- Can modify any file
- Can execute any command
- Can compromise entire system

**After (badips user with limited sudo):**
- No system file access (except owned directories)
- Can only execute specific nft commands via sudo
- Cannot modify configurations
- Cannot elevate privileges beyond nft
- Compromised daemon limited to adding/removing IPs from nftables sets

### Remaining Risks

1. **sudo nft access:**
   - Could add arbitrary IPs to block sets (DoS potential)
   - Mitigated: That's the daemon's intended function
   - Mitigated: Admin can monitor sudo logs

2. **Configuration file read access:**
   - Can read database passwords from config
   - Mitigated: Standard for service accounts, necessary for operation
   - Mitigated: Config files should have restricted permissions (640)

3. **Log injection:**
   - Could write arbitrary data to logs
   - Mitigated: Logs in dedicated directory, not system logs
   - Mitigated: Standard risk for any service

### Comparison to Current State

**Current (root):**
- Risk: HIGH - Full system compromise possible
- Impact: CRITICAL - Complete system control

**Proposed (badips user):**
- Risk: MEDIUM - Limited to nftables manipulation
- Impact: LOW-MEDIUM - Can block IPs (DoS) but cannot compromise system

**Verdict:** Significant security improvement with minimal operational complexity.

## Rollback Plan

If issues arise:

1. **Immediate rollback (modify drop-in file):**
   ```bash
   # Edit the systemd drop-in to use root
   cat > /etc/systemd/system/bad_ips.service.d/user.conf <<EOF
   [Service]
   User=root
   Group=root
   EOF

   systemctl daemon-reload
   systemctl restart bad_ips
   ```

2. **Or via package downgrade:**
   - Keep old version available
   - Can downgrade with `dpkg -i bad-ips_OLD_VERSION.deb`
   - Downgrade will restore root-based operation

## User Requirements & Decisions

Based on user feedback and requirements:

1. ✅ **Username Configuration**: Prompted in install.sh, default "badips", stored in `/etc/default/bad_ips`
2. ✅ **SystemD Best Practice**: Use `User=` and `Group=` directives via drop-in file
3. ✅ **Log Access Groups**: Use standard system groups instead of custom:
   - `systemd-journal`: For journalctl access (standard practice)
   - `adm`: For /var/log access (Debian/Ubuntu standard)
4. ✅ **Sudo Scope**: Specific to inet badips table only (most secure)
5. ✅ **User Config**: System user, no home dir, nologin shell
6. ✅ **Sudo Password**: NOPASSWD with limited commands (required for automation)

## Additional Security Measures Identified

Beyond the original plan, the following security measures were added:

1. **Configuration File Security** (CRITICAL):
   - Database passwords stored in plaintext in config files
   - Solution: chmod 640, chown root:$BADIPS_GROUP
   - Prevents privilege escalation while allowing necessary read access

2. **Sudoers Validation**:
   - Validate with `visudo -c` before installation
   - Remove file and fail installation if validation fails
   - Prevents broken sudo configuration

3. **SystemD Drop-in Architecture**:
   - Base service file remains generic in package
   - User configuration in separate drop-in file
   - Cleaner upgrades, no merge conflicts
   - Standard systemd best practice

4. **Supplementary Groups**:
   - `SupplementaryGroups=` directive in systemd
   - Ensures proper group membership even if usermod fails
   - More reliable than relying solely on usermod

5. **Configuration Persistence**:
   - Username stored in `/etc/default/bad_ips`
   - Survives package upgrades
   - Allows custom usernames beyond "badips"

## Conclusion

This enhanced implementation follows security best practices and addresses all user requirements:

**Security Benefits:**
- ✅ Principle of least privilege - service runs with minimal necessary permissions
- ✅ Attack surface reduction - compromised daemon cannot modify system files
- ✅ Configuration security - database passwords protected with proper permissions
- ✅ Audit trail - all nft operations logged via sudo
- ✅ Well-established pattern (used by nginx, apache, mysql, postgresql, etc.)

**Operational Benefits:**
- ✅ Configurable username (not hardcoded to "badips")
- ✅ Standard system groups (systemd-journal, adm) for log access
- ✅ SystemD drop-in architecture for cleaner upgrades
- ✅ Validated sudoers configuration prevents system breakage
- ✅ Easy rollback if issues arise

**Implementation Quality:**
- ✅ Handles fresh installations and upgrades gracefully
- ✅ Fallback mechanisms for robustness (postinst creates user if install.sh didn't)
- ✅ Comprehensive validation (username format, sudoers syntax, file permissions)
- ✅ Good balance of security vs. usability
- ✅ Follows Debian/Ubuntu packaging best practices

**Risk Assessment:**
- **Current State**: HIGH risk - full root access, complete system compromise possible
- **Proposed State**: MEDIUM-LOW risk - limited to nftables manipulation, cannot compromise system
- **Implementation Risk**: LOW - straightforward changes, well-tested patterns, easy rollback

**Recommendation**: **Implement as proposed**. This is a significant security improvement with low implementation risk and high confidence in success.
