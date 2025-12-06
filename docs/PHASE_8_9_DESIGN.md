# Phase 8 & 9 Design: AI Review and Reporting

## Phase 8: AI IP Review for Gatherer

### Overview
Implement AI-based analysis of blocked IPs to identify false positives and assess reputation before propagating blocks across the infrastructure.

### Architecture

#### 1. Asynchronous Analysis
- **Fork/Thread Model**: Analysis runs in separate thread/fork to avoid blocking propagation
- **Queue System**: New IPs enter analysis queue
- **Results Cache**: AI analysis results stored in SQLite with timestamp
- **Next Propagation**: Results applied on next propagation cycle

#### 2. AI Analysis Components

##### A. False Positive Detection
Analyze patterns to identify legitimate traffic:
- **Login patterns**: Distinguish between brute force and legitimate failed logins
- **Rate analysis**: Compare request rates against normal baselines
- **Service correlation**: Cross-reference blocks across multiple services
- **Time-based patterns**: Identify business hours vs. attack patterns

##### B. Reputation Scoring
Multi-source reputation analysis:
- **AbuseIPDB API**: Query known abuse databases
- **Shodan/Censys**: Infrastructure reputation
- **Commercial feeds**: Optional integration (e.g., ThreatFox, AlienVault OTX)
- **Historical data**: Track repeat offenders

##### C. Confidence Intervals
Scoring system: 0-100
- **0-30**: Low confidence (likely false positive) → Don't propagate
- **31-70**: Medium confidence → Propagate with warning flag
- **71-100**: High confidence (definitely malicious) → Propagate immediately

#### 3. Database Schema Extension

```sql
CREATE TABLE IF NOT EXISTS ip_analysis (
    ip TEXT PRIMARY KEY,
    confidence_score INTEGER,          -- 0-100
    false_positive_score INTEGER,      -- 0-100 (higher = more likely FP)
    reputation_sources TEXT,           -- JSON: {"abuseipdb": 95, "shodan": 80}
    analysis_timestamp INTEGER,
    last_updated INTEGER,
    ai_verdict TEXT,                   -- 'malicious', 'suspicious', 'likely_clean'
    reasoning TEXT,                    -- Human-readable explanation
    whois_data TEXT,                   -- Cached whois (for Phase 9)
    country_code TEXT                  -- For reporting
);
```

#### 4. Configuration Parameters

Add to `badips.conf`:

```ini
[ai_analysis]
enabled = 1
confidence_threshold = 70           # Minimum score to propagate
analysis_threads = 2                # Parallel analysis workers
cache_ttl = 604800                  # Cache analysis for 7 days
abuseipdb_key = YOUR_API_KEY        # Optional: AbuseIPDB API key
check_reputation = 1                # Query external reputation services
ai_model = claude                   # 'claude', 'local', or 'none'
```

#### 5. Implementation Steps

1. **Add analysis queue table** to SQLite
2. **Create AI analyzer module**: `BadIPs::AI.pm`
3. **Integrate with gatherer loop**:
   - Before propagation: Check if IP has analysis
   - Queue IPs without analysis
   - Background thread processes queue
4. **Add CLI command**: `bad_ips --analyze-ip <IP>` for manual testing
5. **Logging**: Detailed logging of AI decisions

---

## Phase 9: Gatherer Reporting System

### Overview
Comprehensive reporting system providing visibility into blocked IPs across the infrastructure.

### Report Types

#### 1. Real-Time Status Report
**Triggered**: On-demand via CLI or web interface

**Data Collected**:
- Per-hunter blocked IP counts
- Per-hunter most recent blocks
- Aggregate statistics
- Service breakdown (SSH vs. Mail vs. DNS)

**Output Format**:
```
=== Bad IPs Status Report ===
Generated: 2025-12-06 12:34:56

--- Per-Hunter Summary ---
proxy:    1,234 blocked IPs (nginx: 800, ssh: 434)
mail:     2,456 blocked IPs (postfix: 2,100, ssh: 356)
dovecot:  1,890 blocked IPs (dovecot: 1,600, ssh: 290)
ns01:       567 blocked IPs (named: 400, ssh: 167)
ns02:       543 blocked IPs (named: 380, ssh: 163)
ns03:       521 blocked IPs (named: 360, ssh: 161)
nas:        234 blocked IPs (nfs: 120, smb: 80, ssh: 34)

--- Aggregate Statistics ---
Total Unique IPs:     5,678
Total Blocks (sum):   7,445
Average per hunter:   1,063
Most active hunter:   mail (2,456 blocks)

--- Recent Activity (Last 24h) ---
New blocks:    234
Expired:        89
Net change:   +145
```

#### 2. Whois Lookup System

**Features**:
- **On-demand**: `bad_ips --report --whois`
- **Caching**: Store whois results in `ip_analysis` table
- **CIDR detection**: Identify IP block from whois, cache for entire block
- **Rate limiting**: Respect whois server limits (queries per minute)

**Implementation**:
```perl
sub _get_whois_cached {
    my ($self, $ip) = @_;

    # Check cache first
    my $cached = $self->_db_get_whois($ip);
    return $cached if $cached && (time - $cached->{timestamp}) < 2592000; # 30 days

    # Perform whois lookup
    my $whois_data = $self->_whois_lookup($ip);

    # Extract CIDR block
    my $cidr = $self->_extract_cidr($whois_data);

    # Cache for entire block
    $self->_db_cache_whois($cidr, $whois_data);

    return $whois_data;
}
```

#### 3. Country-Based Analysis

**Report Output**:
```
=== Top Offending Countries ===
1. CN (China):         1,234 IPs (21.7%)
2. RU (Russia):          987 IPs (17.4%)
3. US (United States):   654 IPs (11.5%)
4. BR (Brazil):          432 IPs (7.6%)
5. IN (India):           398 IPs (7.0%)
...
```

**Features**:
- GeoIP lookup integration (MaxMind GeoLite2)
- Country code extraction from whois
- Visualization-ready data (CSV/JSON export)

#### 4. Cyclic Reporting

**Configuration**:
```ini
[reporting]
enabled = 1
report_interval = 3600              # Generate report every hour
report_path = /var/lib/bad_ips/reports
format = text,json,html             # Output formats
email_report = admin@example.com    # Optional: email reports
retention_days = 30                 # Keep reports for 30 days
```

**Report Types**:
- **Hourly**: Quick stats, new blocks
- **Daily**: Full analysis with country breakdown
- **Weekly**: Trends, top offenders, recommendations

#### 5. Advanced Reporting Features

##### A. Trend Analysis
- Block rate over time
- Peak attack times (hourly heatmap)
- Service-specific trends

##### B. Hunter Comparison
- Identify hunters under heavy attack
- Compare block patterns across hunters
- Detect configuration issues (one hunter blocking everything)

##### C. IP Lifecycle Tracking
```
IP: 1.2.3.4
First seen:      2025-12-01 08:23:45 (mail server)
Total blocks:    15
Services:        postfix (12), ssh (3)
Last blocked:    2025-12-06 14:32:10
Expires:         2025-12-14 14:32:10
Whois:           China Telecom (CN)
AI Verdict:      Malicious (confidence: 98%)
Propagated:      Yes (6/7 hunters)
```

##### D. Export Formats
- **Text**: Human-readable console output
- **JSON**: Machine-readable for dashboards
- **HTML**: Web-based reports with charts
- **CSV**: Excel-compatible for analysis
- **Prometheus**: Metrics endpoint for monitoring

### Database Schema for Reporting

```sql
CREATE TABLE IF NOT EXISTS report_cache (
    report_type TEXT,               -- 'hourly', 'daily', 'weekly'
    report_date INTEGER,            -- Unix timestamp
    report_data TEXT,               -- JSON blob
    PRIMARY KEY (report_type, report_date)
);

CREATE TABLE IF NOT EXISTS whois_cache (
    cidr TEXT PRIMARY KEY,          -- Network block (e.g., 1.2.3.0/24)
    whois_data TEXT,                -- Full whois output
    country_code TEXT,
    organization TEXT,
    cached_at INTEGER,
    expires_at INTEGER
);
```

### CLI Interface

```bash
# Generate reports
bad_ips --report                          # Quick status
bad_ips --report --detailed               # Full report with whois
bad_ips --report --format json            # JSON output
bad_ips --report --country                # Country analysis
bad_ips --report --export /tmp/report.csv # Export to CSV

# Historical reports
bad_ips --report --history 7d             # Last 7 days
bad_ips --report --trends                 # Trend analysis

# Specific IP analysis
bad_ips --analyze-ip 1.2.3.4              # Full analysis of single IP
```

### Web Dashboard (Optional Future Enhancement)
- Real-time monitoring
- Interactive charts
- Click to drill down
- Export functionality

---

## Implementation Priority

### Phase 8: AI Review (3-4 days)
1. Database schema updates (2 hours)
2. AI analyzer module (1 day)
3. Reputation service integrations (1 day)
4. Testing and tuning (1-2 days)

### Phase 9: Reporting (4-5 days)
1. Basic reporting infrastructure (1 day)
2. Whois caching system (1 day)
3. Country analysis / GeoIP (1 day)
4. Export formats and CLI (1 day)
5. Cyclic reporting scheduler (1 day)

---

## Dependencies

### Perl Modules Needed
```perl
# Phase 8
use LWP::UserAgent;      # HTTP requests for reputation APIs
use JSON;                # Parse API responses
use Thread::Queue;       # Analysis queue

# Phase 9
use Net::Whois::Raw;     # Whois lookups
use GeoIP2::Database::Reader;  # Country lookups (optional)
use Text::CSV;           # CSV export
```

### External Services (Optional)
- AbuseIPDB API (free tier: 1000 requests/day)
- MaxMind GeoLite2 (free, requires registration)
- Claude API (for AI analysis)

---

## Configuration Template Updates

Add to gatherer template:

```ini
[ai_analysis]
enabled = 1
confidence_threshold = 70
analysis_threads = 2
cache_ttl = 604800
abuseipdb_key =

[reporting]
enabled = 1
report_interval = 3600
report_path = /var/lib/bad_ips/reports
format = text,json
whois_cache_ttl = 2592000
email_report =
```

---

## Success Criteria

### Phase 8
- [ ] AI analysis integrated into gatherer loop
- [ ] Confidence scoring working correctly
- [ ] False positives reduced by at least 50%
- [ ] Reputation checks functioning
- [ ] Async processing not blocking propagation

### Phase 9
- [ ] Real-time reports showing accurate data
- [ ] Whois caching reducing redundant queries
- [ ] Country analysis identifying top offenders
- [ ] Cyclic reports generating on schedule
- [ ] All export formats working (text, JSON, CSV, HTML)
- [ ] CLI interface intuitive and fast

---

## Testing Plan

1. **Phase 8 Testing**
   - Test with known good IPs (should score low confidence)
   - Test with known bad IPs (should score high confidence)
   - Measure impact on propagation latency
   - Verify async processing

2. **Phase 9 Testing**
   - Generate report with 1000+ IPs
   - Verify whois caching efficiency
   - Test all export formats
   - Load test with multiple concurrent reports
