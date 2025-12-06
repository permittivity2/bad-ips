#!/usr/bin/env perl
#
# Bad IPs Database Migration Script
# Migrates from v1 schema (jailed_ips only) to v2 schema (blocked_ips + propagation_status)
#
# Usage: sudo perl migrate_database_v2.pl [--db-path /path/to/bad_ips.sql] [--dry-run]
#

use strict;
use warnings;
use DBI;
use Getopt::Long;
use File::Copy;
use POSIX qw(strftime);

# Configuration
my $db_path = '/var/lib/bad_ips/bad_ips.sql';
my $dry_run = 0;
my $hostname = `hostname -s 2>/dev/null` || 'unknown';
chomp $hostname;

GetOptions(
    'db-path=s' => \$db_path,
    'dry-run'   => \$dry_run,
    'help'      => sub { print_usage(); exit 0; }
) or die "Error in command line arguments\n";

print "=" x 70 . "\n";
print "Bad IPs Database Migration Script - v1 to v2\n";
print "=" x 70 . "\n\n";

# Validate database exists
unless (-f $db_path) {
    die "ERROR: Database not found at $db_path\n";
}

print "[INFO] Database: $db_path\n";
print "[INFO] Hostname: $hostname\n";
print "[INFO] Dry-run: " . ($dry_run ? "YES" : "NO") . "\n\n";

# Backup database
unless ($dry_run) {
    my $backup_path = $db_path . ".backup." . time();
    print "[INFO] Creating backup: $backup_path\n";
    copy($db_path, $backup_path) or die "Backup failed: $!\n";
    print "[OK] Backup created\n\n";
}

# Connect to database
my $dbh = DBI->connect("dbi:SQLite:dbname=$db_path", "", "", {
    RaiseError => 1,
    AutoCommit => 1,
    sqlite_unicode => 1
}) or die "Cannot connect to database: $DBI::errstr\n";

print "[INFO] Connected to database\n\n";

# Check current schema version
my $version = get_schema_version($dbh);
print "[INFO] Current schema version: $version\n\n";

if ($version >= 2) {
    print "[WARN] Database already at version 2 or higher. Nothing to do.\n";
    exit 0;
}

# Start migration
print "=" x 70 . "\n";
print "Starting Migration\n";
print "=" x 70 . "\n\n";

if ($dry_run) {
    print "[DRY-RUN] Would create new tables and migrate data\n";
    dry_run_check($dbh);
} else {
    perform_migration($dbh);
}

$dbh->disconnect;

print "\n" . "=" x 70 . "\n";
print "Migration Complete!\n";
print "=" x 70 . "\n";

exit 0;

#------------------------------------------------------------------------------
# Subroutines
#------------------------------------------------------------------------------

sub print_usage {
    print <<'EOF';
Usage: migrate_database_v2.pl [OPTIONS]

Options:
  --db-path PATH    Path to bad_ips.sql database (default: /var/lib/bad_ips/bad_ips.sql)
  --dry-run         Show what would be done without making changes
  --help            Show this help message

Examples:
  # Perform migration
  sudo perl migrate_database_v2.pl

  # Test migration without changes
  sudo perl migrate_database_v2.pl --dry-run

  # Migrate custom database path
  sudo perl migrate_database_v2.pl --db-path /tmp/test.sql
EOF
}

sub get_schema_version {
    my ($dbh) = @_;

    # Check if schema_version table exists
    my $tables = $dbh->selectall_arrayref(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    );

    if (@$tables == 0) {
        return 1;  # No schema_version table = version 1
    }

    # Get version
    my ($version) = $dbh->selectrow_array("SELECT version FROM schema_version LIMIT 1");
    return $version || 1;
}

sub dry_run_check {
    my ($dbh) = @_;

    print "\n[DRY-RUN] Checking current data:\n";

    # Count existing records
    my ($count) = $dbh->selectrow_array("SELECT COUNT(*) FROM jailed_ips");
    print "[INFO] Found $count records in jailed_ips table\n";

    if ($count > 0) {
        print "[INFO] Sample records that would be migrated:\n";
        my $samples = $dbh->selectall_arrayref(
            "SELECT ip, datetime(first_jailed_at, 'unixepoch') as blocked_time
             FROM jailed_ips LIMIT 5",
            { Slice => {} }
        );

        foreach my $row (@$samples) {
            print "  - IP: $row->{ip}, Blocked: $row->{blocked_time}\n";
        }
    }

    print "\n[DRY-RUN] New tables that would be created:\n";
    print "  1. blocked_ips (track block origins and metadata)\n";
    print "  2. propagation_status (track where IPs are propagated)\n";
    print "  3. schema_version (track database version)\n";
}

sub perform_migration {
    my ($dbh) = @_;

    $dbh->begin_work;

    eval {
        # Step 1: Create new tables
        print "[1/5] Creating new tables...\n";
        create_new_tables($dbh);
        print "[OK] New tables created\n\n";

        # Step 2: Migrate existing data
        print "[2/5] Migrating existing jailed_ips data...\n";
        migrate_jailed_ips($dbh);
        print "[OK] Data migrated\n\n";

        # Step 3: Create indexes
        print "[3/5] Creating indexes...\n";
        create_indexes($dbh);
        print "[OK] Indexes created\n\n";

        # Step 4: Set schema version
        print "[4/5] Setting schema version to 2...\n";
        set_schema_version($dbh, 2);
        print "[OK] Schema version updated\n\n";

        # Step 5: Verify migration
        print "[5/5] Verifying migration...\n";
        verify_migration($dbh);
        print "[OK] Verification passed\n\n";

        $dbh->commit;
    };

    if ($@) {
        print "[ERROR] Migration failed: $@\n";
        print "[INFO] Rolling back changes...\n";
        $dbh->rollback;
        die "Migration aborted\n";
    }
}

sub create_new_tables {
    my ($dbh) = @_;

    # Create blocked_ips table
    $dbh->do(<<'SQL');
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT NOT NULL,
    originating_server TEXT NOT NULL,
    originating_service TEXT NOT NULL,
    detector_name TEXT NOT NULL,
    pattern_matched TEXT,
    matched_log_line TEXT,
    first_blocked_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    block_count INTEGER DEFAULT 1,
    PRIMARY KEY (ip, originating_server)
)
SQL

    # Create propagation_status table
    $dbh->do(<<'SQL');
CREATE TABLE IF NOT EXISTS propagation_status (
    ip TEXT NOT NULL,
    target_server TEXT NOT NULL,
    status TEXT NOT NULL,
    propagated_at INTEGER,
    last_attempt INTEGER,
    attempt_count INTEGER DEFAULT 0,
    error_message TEXT,
    PRIMARY KEY (ip, target_server),
    FOREIGN KEY (ip) REFERENCES blocked_ips(ip) ON DELETE CASCADE
)
SQL

    # Create schema_version table
    $dbh->do(<<'SQL');
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    upgraded_at INTEGER NOT NULL
)
SQL
}

sub migrate_jailed_ips {
    my ($dbh) = @_;

    # Migrate existing jailed_ips to blocked_ips
    # Since we don't have metadata for old entries, use defaults
    $dbh->do(<<SQL);
INSERT INTO blocked_ips (
    ip, originating_server, originating_service, detector_name,
    pattern_matched, matched_log_line,
    first_blocked_at, last_seen_at, expires_at, block_count
)
SELECT
    ip,
    '$hostname' as originating_server,
    'unknown' as originating_service,
    'migrated' as detector_name,
    'migrated from v1' as pattern_matched,
    'No metadata available (migrated from v1 schema)' as matched_log_line,
    first_jailed_at,
    last_jailed_at,
    expires_at,
    1 as block_count
FROM jailed_ips
WHERE expires_at > strftime('%s', 'now')
SQL

    my $migrated = $dbh->selectrow_array("SELECT changes()");
    print "[INFO] Migrated $migrated active blocks\n";
}

sub create_indexes {
    my ($dbh) = @_;

    $dbh->do("CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires ON blocked_ips(expires_at)");
    $dbh->do("CREATE INDEX IF NOT EXISTS idx_blocked_ips_service ON blocked_ips(originating_service)");
    $dbh->do("CREATE INDEX IF NOT EXISTS idx_blocked_ips_server ON blocked_ips(originating_server)");
    $dbh->do("CREATE INDEX IF NOT EXISTS idx_propagation_status ON propagation_status(status)");
    $dbh->do("CREATE INDEX IF NOT EXISTS idx_propagation_pending ON propagation_status(status, last_attempt)");
}

sub set_schema_version {
    my ($dbh, $version) = @_;

    $dbh->do("DELETE FROM schema_version");  # Clear any old versions
    $dbh->do("INSERT INTO schema_version (version, upgraded_at) VALUES (?, ?)",
             undef, $version, time());
}

sub verify_migration {
    my ($dbh) = @_;

    # Check tables exist
    my @required_tables = qw(blocked_ips propagation_status schema_version);
    foreach my $table (@required_tables) {
        my ($exists) = $dbh->selectrow_array(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
            undef, $table
        );
        die "Table $table not found!" unless $exists;
    }

    # Check schema version
    my ($version) = $dbh->selectrow_array("SELECT version FROM schema_version");
    die "Schema version not set correctly!" unless $version == 2;

    # Check data migrated
    my ($blocked_count) = $dbh->selectrow_array("SELECT COUNT(*) FROM blocked_ips");
    print "[INFO] blocked_ips table has $blocked_count records\n";
}
