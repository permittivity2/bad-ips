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

### 1. Create badips System User

**User Specifications (per user answers):**
- Username: `badips`
- Type: System user (UID < 1000)
- Home: `/nonexistent` (no home directory)
- Shell: `/usr/sbin/nologin` (no interactive login)
- Groups: Just primary group `badips`
- Purpose: Service account for bad_ips daemon

**Creation Method:**
```bash
# In DEBIAN/postinst
if ! getent passwd badips > /dev/null; then
    adduser --system --group --no-create-home \
        --home /nonexistent --shell /usr/sbin/nologin \
        badips
    echo "Created system user: badips"
fi
```

**Rationale:**
- `--system`: Creates system user (UID < 1000)
- `--group`: Creates matching group
- `--no-create-home`: No home directory needed
- `--home /nonexistent`: Standard for service accounts
- `--shell /usr/sbin/nologin`: Prevents interactive login

### 2. Configure sudoers Rule

**Sudoers File:** `/etc/sudoers.d/bad_ips` (mode 0440)

**Rule Specification (per user answers):**
- User: `badips`
- NOPASSWD: Yes (required for automated operation)
- Scope: Limited to `inet badips` table only
- Commands: Only necessary nft operations

**Sudoers Content:**
```sudoers
# Bad IPs sudoers configuration
# Allows badips user to manage the inet badips nftables table
# Created by bad-ips package installation

# Command aliases for allowed nft operations
Cmnd_Alias NFT_BADIPS_ADD = /usr/sbin/nft add element inet badips badipv4 *
Cmnd_Alias NFT_BADIPS_ADD_V6 = /usr/sbin/nft add element inet badips badipv6 *
Cmnd_Alias NFT_BADIPS_FLUSH = /usr/sbin/nft flush set inet badips never_block*, \
                              /usr/sbin/nft flush set inet badips always_block*
Cmnd_Alias NFT_BADIPS_LIST = /usr/sbin/nft -j list ruleset, \
                             /usr/sbin/nft list ruleset

# Allow badips user to run these commands without password
badips ALL=(root) NOPASSWD: NFT_BADIPS_ADD, NFT_BADIPS_ADD_V6, NFT_BADIPS_FLUSH, NFT_BADIPS_LIST
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

### 3. Update systemd Service File

**File:** `/etc/systemd/system/bad_ips.service`

**Changes:**
```ini
[Unit]
Description=Bad IP Blocking Service
After=network.target nftables.service
Wants=nftables.service
ConditionPathExists=/etc/nftables.d/99-badips.nft

[Service]
Type=simple
User=badips                    # NEW: Run as badips user instead of root
Group=badips                   # NEW: Run as badips group
ExecStart=/bin/sh -c 'tail -F /var/log/bad_ips/bad_ips.log | systemd-cat -t bad_ips & exec /usr/local/sbin/bad_ips'
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
TimeoutStopSec=300
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Key Changes:**
- Added `User=badips`
- Added `Group=badips`
- Removed `User=root` (if present)

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

### 5. Update File/Directory Ownership

**In DEBIAN/postinst:**

```bash
# Ensure badips user owns necessary directories
chown -R badips:badips /var/lib/bad_ips
chown -R badips:badips /var/log/bad_ips

# Ensure correct permissions
chmod 755 /var/lib/bad_ips
chmod 755 /var/log/bad_ips
chmod 640 /var/log/bad_ips/bad_ips.log 2>/dev/null || true
```

**Rationale:**
- badips user must be able to write to state directory
- badips user must be able to write to log directory
- Configuration files remain root-owned (read-only for badips)

## Implementation Steps

### Phase 1: Package Changes

1. **Update DEBIAN/postinst:**
   - Add user creation logic (with existence check)
   - Add directory ownership changes
   - Add sudoers file installation
   - Add sudoers file validation

2. **Update DEBIAN/postrm:**
   - Add user removal logic (on purge only)
   - Add sudoers file removal

3. **Update etc/systemd/system/bad_ips.service:**
   - Add `User=badips`
   - Add `Group=badips`

4. **Update usr/local/lib/site_perl/BadIPs/NFT.pm:**
   - Prepend `sudo ` to all nft commands

5. **Add etc/sudoers.d/bad_ips:**
   - Create sudoers file with proper permissions
   - Include in package

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

### 1. `DEBIAN/postinst`
**Changes:**
- Add user creation logic
- Add sudoers file installation
- Update directory ownership
- Add validation checks

### 2. `DEBIAN/postrm`
**Changes:**
- Add user removal (on purge)
- Remove sudoers file

### 3. `etc/systemd/system/bad_ips.service`
**Changes:**
- Add `User=badips`
- Add `Group=badips`

### 4. `usr/local/lib/site_perl/BadIPs/NFT.pm`
**Changes:**
- Line ~112: `nft add element` → `sudo nft add element`
- Line ~205: `nft -j list ruleset` → `sudo nft -j list ruleset`
- Line ~241: `nft flush set` → `sudo nft flush set`
- Line ~257: `nft add element` → `sudo nft add element`

### 5. `etc/sudoers.d/bad_ips` (NEW FILE)
**Content:**
- Command aliases for allowed nft operations
- sudoers rule for badips user

### 6. Build System
**Changes:**
- Ensure `etc/sudoers.d/bad_ips` is included in package
- Set correct permissions (0440) during package build

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

1. **Immediate rollback:**
   ```bash
   # Edit service file
   sed -i 's/User=badips/User=root/' /etc/systemd/system/bad_ips.service
   sed -i 's/Group=badips/Group=badips/' /etc/systemd/system/bad_ips.service
   systemctl daemon-reload
   systemctl restart bad_ips
   ```

2. **Or via package downgrade:**
   - Keep old version available
   - Can downgrade with `dpkg -i bad-ips_OLD_VERSION.deb`

## User Answers Summary

Based on clarification questions:

1. ✅ **User Creation**: Automatic during postinst
2. ✅ **Sudo Scope**: Specific to inet badips table only (most secure)
3. ✅ **User Config**: System user, no home dir, nologin shell
4. ✅ **Sudo Password**: NOPASSWD with limited commands (required for automation)

## Conclusion

This implementation follows security best practices:
- ✅ Principle of least privilege
- ✅ Well-established pattern (used by nginx, apache, mysql, etc.)
- ✅ Minimal complexity (straightforward implementation)
- ✅ Good balance of security vs. usability
- ✅ Easy rollback if needed

**Recommendation**: Implement as proposed. This is a clear security win with low risk.
