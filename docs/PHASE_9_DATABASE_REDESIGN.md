# Phase 9: Database Redesign for Block Tracking and Propagation Visibility

## Problem Statement

Current database (`jailed_ips` table) only tracks:
- IP address
- First/last jail time
- Expiration time

**Missing critical information:**
- Which server originally blocked the IP?
- Which service triggered the block (nginx, sshd, postfix)?
- Which detector pattern matched?
- Where has this IP been propagated?
- Did propagation succeed or fail?

**Impact:** Cannot debug false positives or track propagation status.

**Example:** IP 166.199.99.47 was blocked, but we couldn't easily tell:
- That it was blocked by nginx on proxy
- That it was a false positive from a session timeout
- Whether it propagated to other servers

---

## New Database Schema

### Table 1: `blocked_ips` (Master Block Records)

Tracks the **origin** of each block - which server first detected it and why.

```sql
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT NOT NULL,
    originating_server TEXT NOT NULL,      -- Hunter that first blocked it
    originating_service TEXT NOT NULL,     -- nginx, sshd, postfix, dovecot, named, nfs, smb
    detector_name TEXT NOT NULL,           -- e.g., "nginx", "sshd", "postfix"
    pattern_matched TEXT,                  -- Which regex pattern triggered block
    matched_log_line TEXT,                 -- Sample log line that triggered (truncated)
    first_blocked_at INTEGER NOT NULL,     -- Unix epoch when first blocked
    last_seen_at INTEGER NOT NULL,         -- Last time this IP triggered pattern
    expires_at INTEGER NOT NULL,           -- When block expires
    block_count INTEGER DEFAULT 1,         -- How many times this IP triggered blocks
    PRIMARY KEY (ip, originating_server)
);

CREATE INDEX idx_blocked_ips_expires ON blocked_ips(expires_at);
CREATE INDEX idx_blocked_ips_service ON blocked_ips(originating_service);
CREATE INDEX idx_blocked_ips_server ON blocked_ips(originating_server);
```

**Fields Explained:**
- `ip`: The blocked IP address
- `originating_server`: Hostname of hunter that blocked it (e.g., "proxy", "mail")
- `originating_service`: Service that was attacked (e.g., "nginx", "sshd")
- `detector_name`: Name from detector config (e.g., "nginx", "sshd", "postfix")
- `pattern_matched`: The regex pattern that matched (for debugging)
- `matched_log_line`: Sample of the log line (first 500 chars, for context)
- `first_blocked_at`: When this server first blocked this IP
- `last_seen_at`: Most recent attack from this IP
- `expires_at`: When the block expires (first_blocked_at + blocking_time)
- `block_count`: Repeat offense counter

---

### Table 2: `propagation_status` (Propagation Tracking)

Tracks where each blocked IP has been **propagated** (or needs to be).

```sql
CREATE TABLE IF NOT EXISTS propagation_status (
    ip TEXT NOT NULL,
    target_server TEXT NOT NULL,           -- Server that should have the block
    status TEXT NOT NULL,                  -- 'pending', 'propagated', 'failed', 'expired'
    propagated_at INTEGER,                 -- When successfully propagated (NULL if pending)
    last_attempt INTEGER,                  -- Last propagation attempt timestamp
    attempt_count INTEGER DEFAULT 0,       -- Number of propagation attempts
    error_message TEXT,                    -- Last error if failed
    PRIMARY KEY (ip, target_server),
    FOREIGN KEY (ip) REFERENCES blocked_ips(ip) ON DELETE CASCADE
);

CREATE INDEX idx_propagation_status ON propagation_status(status);
CREATE INDEX idx_propagation_pending ON propagation_status(status, last_attempt);
```

**Fields Explained:**
- `ip`: The IP being propagated
- `target_server`: Server that should receive the block (e.g., "ns01", "mail")
- `status`:
  - `pending`: Needs propagation (queued)
  - `propagated`: Successfully propagated
  - `failed`: Propagation failed (will retry)
  - `expired`: Block expired before propagation
- `propagated_at`: Timestamp of successful propagation
- `last_attempt`: Last time we tried to propagate
- `attempt_count`: Retry counter (for detecting persistent failures)
- `error_message`: SSH error or other failure reason

---

### Table 3: `jailed_ips` (Legacy/Compatibility)

**Keep for now** to maintain compatibility during transition. Will be deprecated.

```sql
-- Existing table, no changes
CREATE TABLE IF NOT EXISTS jailed_ips (
    ip TEXT PRIMARY KEY,
    first_jailed_at INTEGER,
    last_jailed_at INTEGER,
    expires_at INTEGER
);
```

**Migration Strategy:** Gradually phase out, keeping it populated for now.

---

## Data Flow

### Hunter Mode (e.g., proxy, mail, ns01)

1. **Detect Attack**: Log pattern matches
2. **Capture Metadata**:
   - Which service (nginx, sshd, etc.)
   - Which detector/pattern
   - Sample log line
3. **Insert into `blocked_ips`**:
   ```sql
   INSERT INTO blocked_ips (ip, originating_server, originating_service,
                            detector_name, pattern_matched, matched_log_line,
                            first_blocked_at, last_seen_at, expires_at, block_count)
   VALUES ('1.2.3.4', 'proxy', 'nginx', 'nginx',
           'pattern4: "request_uri":"[^"]*error\.php',
           'proxy nginx: {"remote_addr":"1.2.3.4"...}',
           1733500000, 1733500000, 1734191200, 1);
   ```
4. **Block locally** with nftables
5. **Also insert into `jailed_ips`** (for backward compatibility)

### Gatherer Mode (administrator)

1. **Poll hunters** via SSH every `propagation_delay` seconds
2. **For each hunter**, query their `blocked_ips` table:
   ```sql
   SELECT ip, originating_server, originating_service, detector_name,
          pattern_matched, first_blocked_at, expires_at
   FROM blocked_ips WHERE expires_at > UNIX_TIMESTAMP();
   ```
3. **Merge into gatherer's `blocked_ips` table**:
   - Insert if new
   - Update `last_seen_at` if exists
4. **Create propagation tasks**:
   ```sql
   -- For each IP from hunter 'proxy', create propagation entries for all other servers
   INSERT OR IGNORE INTO propagation_status (ip, target_server, status, last_attempt, attempt_count)
   SELECT '1.2.3.4', server_name, 'pending', 0, 0
   FROM (VALUES ('mail'), ('dovecot'), ('ns01'), ('ns02'), ('ns03'), ('nas'))
   WHERE server_name != 'proxy';  -- Don't propagate back to origin
   ```
5. **Execute propagation**:
   - For each `pending` propagation:
     - SSH to target server
     - Execute: `nft add element inet filter badipv4 { IP timeout TTL }`
     - On success: UPDATE status='propagated', propagated_at=NOW()
     - On failure: UPDATE status='failed', error_message='...', attempt_count++
6. **Retry failed propagations** (with exponential backoff)

---

## Example Database State

### Scenario: IP 166.199.99.47 blocked by proxy's nginx

#### Hunter (proxy) - `blocked_ips` table:
```
ip              | originating_server | originating_service | detector_name | pattern_matched                    | first_blocked_at | expires_at
166.199.99.47   | proxy              | nginx               | nginx         | pattern4: request_uri.*error\.php | 1733508426       | 1734199626
```

#### Gatherer (administrator) - `blocked_ips` table:
```
ip              | originating_server | originating_service | detector_name | pattern_matched                    | first_blocked_at | expires_at
166.199.99.47   | proxy              | nginx               | nginx         | pattern4: request_uri.*error\.php | 1733508426       | 1734199626
```

#### Gatherer (administrator) - `propagation_status` table:
```
ip              | target_server | status      | propagated_at | last_attempt | attempt_count | error_message
166.199.99.47   | mail          | propagated  | 1733508430    | 1733508430   | 1             | NULL
166.199.99.47   | dovecot       | propagated  | 1733508431    | 1733508431   | 1             | NULL
166.199.99.47   | ns01          | propagated  | 1733508432    | 1733508432   | 1             | NULL
166.199.99.47   | ns02          | failed      | NULL          | 1733508433   | 3             | SSH timeout
166.199.99.47   | ns03          | propagated  | 1733508434    | 1733508434   | 1             | NULL
166.199.99.47   | nas           | propagated  | 1733508435    | 1733508435   | 1             | NULL
```

**Insights from this data:**
- IP was blocked by proxy's nginx (pattern4)
- Propagated successfully to 5 servers
- Failed to propagate to ns02 (SSH timeout, 3 attempts)
- Can now query: "Show me all nginx blocks" or "Show me failed propagations"

---

## Useful Queries

### Debugging False Positives
```sql
-- Find all blocks from a specific pattern
SELECT ip, originating_server, matched_log_line
FROM blocked_ips
WHERE pattern_matched LIKE '%error\.php%';

-- Show blocks from specific service
SELECT ip, originating_server, detector_name, pattern_matched
FROM blocked_ips
WHERE originating_service = 'nginx';
```

### Propagation Status
```sql
-- Find IPs that failed to propagate
SELECT ip, target_server, error_message, attempt_count
FROM propagation_status
WHERE status = 'failed'
ORDER BY attempt_count DESC;

-- Show propagation summary for an IP
SELECT ps.target_server, ps.status, ps.propagated_at, bi.originating_server
FROM propagation_status ps
JOIN blocked_ips bi ON ps.ip = bi.ip
WHERE ps.ip = '1.2.3.4';

-- Count blocks by service
SELECT originating_service, COUNT(DISTINCT ip) as ip_count
FROM blocked_ips
GROUP BY originating_service
ORDER BY ip_count DESC;

-- Find servers with most blocks
SELECT originating_server, COUNT(DISTINCT ip) as blocks
FROM blocked_ips
GROUP BY originating_server
ORDER BY blocks DESC;
```

### Health Monitoring
```sql
-- Servers with consistent propagation failures
SELECT target_server, COUNT(*) as failure_count
FROM propagation_status
WHERE status = 'failed'
GROUP BY target_server
HAVING failure_count > 10;

-- IPs blocked in last hour
SELECT ip, originating_server, originating_service,
       datetime(first_blocked_at, 'unixepoch') as blocked_time
FROM blocked_ips
WHERE first_blocked_at > strftime('%s', 'now', '-1 hour');
```

---

## Migration Plan

### Step 1: Add New Tables
Run migration script to create `blocked_ips` and `propagation_status` tables.

### Step 2: Dual-Write Mode
Update BadIPs.pm to write to **both** old and new tables:
- Insert into `jailed_ips` (existing logic)
- Insert into `blocked_ips` (new logic with metadata)

### Step 3: Test
Deploy to administrator and one hunter, verify both tables populate correctly.

### Step 4: Gradual Rollout
Deploy to all hunters once stable.

### Step 5: Cutover
Once confident, switch to reading from new tables only. Keep `jailed_ips` for backwards compatibility (read-only).

### Step 6: Cleanup (Future)
Eventually remove `jailed_ips` table (v2.0.0).

---

## Code Changes Required

### 1. Database Initialization (`_init_db` in BadIPs.pm)
- Add creation of new tables
- Add migration logic to convert existing `jailed_ips` data

### 2. Hunter Block Logic (`_jail_ip`)
**Current:**
```perl
sub _jail_ip {
    my ($self, $ip) = @_;
    # Just insert into jailed_ips
}
```

**New:**
```perl
sub _jail_ip {
    my ($self, $ip, $metadata) = @_;
    # $metadata = {
    #   service => 'nginx',
    #   detector => 'nginx',
    #   pattern => 'pattern4: ...',
    #   log_line => '...'
    # }

    # Insert into blocked_ips with metadata
    # Also insert into jailed_ips for compatibility
}
```

### 3. Detector Pattern Matching
Update detectors to **return metadata** when they match:
```perl
sub _check_detector {
    my ($self, $detector, $log_line) = @_;

    if ($log_line =~ /$pattern/) {
        return {
            matched => 1,
            ip => $extracted_ip,
            service => $detector->{service},
            detector_name => $detector->{name},
            pattern => $pattern_name,
            log_line => substr($log_line, 0, 500)
        };
    }
}
```

### 4. Gatherer Collection (`_gather_from_remote_servers`)
Query new `blocked_ips` table from hunters:
```perl
my $query = "SELECT ip, originating_server, originating_service, detector_name,
                    pattern_matched, first_blocked_at, expires_at
             FROM blocked_ips WHERE expires_at > " . time();
```

### 5. Propagation Logic (`_propagate_blocks`)
- Create propagation entries
- Track status
- Handle retries
- Update propagation_status table

---

## Configuration Changes

Add to `badips.conf`:

```ini
[propagation]
max_retry_attempts = 5         # Max retries for failed propagation
retry_backoff = 300            # Seconds between retries (5 min)
propagation_timeout = 30       # SSH timeout for propagation
```

---

## Benefits

✅ **Visibility**: See exactly why each IP was blocked
✅ **Debugging**: Quickly identify false positives
✅ **Monitoring**: Track propagation failures
✅ **Reporting**: Enable rich analytics (Phase 10)
✅ **AI Ready**: Metadata needed for Phase 11 AI analysis
✅ **Audit Trail**: Complete history of blocks and propagations

---

## Risks & Mitigation

**Risk 1:** Database schema change breaks existing installations
**Mitigation:** Dual-write mode, gradual rollout, keep `jailed_ips` for compatibility

**Risk 2:** Performance impact from complex queries
**Mitigation:** Proper indexing, tested on high-volume server

**Risk 3:** Propagation tracking adds overhead
**Mitigation:** Async processing, batch updates

---

## Testing Plan

1. **Unit tests**: Test database operations
2. **Integration test**: Deploy to administrator + 1 hunter
3. **Trigger blocks**: Generate test attacks, verify metadata captured
4. **Check propagation**: Verify status tracking works
5. **Monitor performance**: Ensure no slowdown
6. **Test failure scenarios**: Disconnect a server, verify retry logic

---

## Timeline

- **Phase 9a (Design)**: 1 hour - DONE
- **Phase 9b (Migration script)**: 1 hour
- **Phase 9c (BadIPs.pm updates)**: 3-4 hours
- **Phase 9d (Gatherer updates)**: 2-3 hours
- **Phase 9e (Testing)**: 2 hours

**Total: ~8-10 hours of focused work**
