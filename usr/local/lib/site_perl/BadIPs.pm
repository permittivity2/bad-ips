package BadIPs;
use strict;
use warnings;
use feature 'state';

use Config::Tiny;
use File::Basename ();
use File::Spec;
use File::Path qw(make_path);
use Time::HiRes qw(time sleep);
use POSIX qw(strftime);
use JSON qw(decode_json);
use DBI;
use DBD::Pg;  # PostgreSQL driver
use Log::Any qw($log);
use Regexp::Common qw(net);
use Net::CIDR qw(cidrlookup);
use Sys::Hostname qw(hostname);
use File::ReadBackwards;

# Threading support
use threads;
use threads::shared;
use Thread::Queue;

our $VERSION = '1.2.0';  # Phase 10: Threading + PostgreSQL

# Service -> how to read + patterns (moved to conf.d, kept empty here)
my %DETECTORS = ();

# Shared threading state
my $shutdown :shared = 0;
my $shutdown_start_time :shared = 0;

# Thread-safe queues (initialized in new())
# These are NOT shared variables themselves, but Thread::Queue handles thread-safety internally
my $ips_to_block_queue;
my $record_blocked_ip_queue;
my $sync_to_central_db_queue;

sub new {
    my ($class, %args) = @_;

    my $self = {
        conf_main  => $args{conf_main} // '/usr/local/etc/badips.conf',
        conf_dir   => $args{conf_dir}  // '/usr/local/etc/badips.d',
        conf       => {},
        dbh        => undef,            # Local SQLite handle
        central_dbh => undef,           # Central PostgreSQL handle
        sth_upsert => undef,
        blocked    => {},               # ip => epoch_expires
        run_count  => 0,
        dry_run    => $args{dry_run} ? 1 : 0,
        remote_state => {},             # for future remote fetch cadence
        threads    => [],               # Thread objects
        queue_exceeded_start => {},     # Track queue overflow times
    };

    bless $self, $class;
    $self->_load_config();
    $self->_init_queues();              # Initialize Thread::Queue objects
    $self->{detectors} = $self->_load_detectors_from_confdir();
    $self->_auto_discover_sources();    # compiles patterns + sources
    $self->_init_db();                  # Local SQLite
    $self->_init_central_db();          # Central PostgreSQL
    $self->_initial_load_blocked_ips();
    return $self;
}

# -------------------- config --------------------
sub _load_config {
    my ($self) = @_;
    my $host = (split(/\./, hostname()))[0];

    my @files = ();
    push @files, $self->{conf_main} if -f $self->{conf_main};
    if (-d $self->{conf_dir}) {
        opendir my $dh, $self->{conf_dir};
        my @extra = sort grep { /\.conf\z/ && -f File::Spec->catfile($self->{conf_dir}, $_) } readdir $dh;
        closedir $dh;
        push @files, map { File::Spec->catfile($self->{conf_dir}, $_) } @extra;
    }

    my %accum = ();
    for my $f (@files) {
        my $c = Config::Tiny->read($f);
        next unless $c;

        # Merge global first
        if (my $g = $c->{global}) {
            %accum = (%accum, %$g);
        }
        # Host override
        if (my $h = $c->{"host:$host"}) {
            %accum = (%accum, %$h);
        }
    }

    # Defaults if missing
    $accum{blocking_time}             //= 86400 * 8;
    $accum{sleep_time}                //= 1;
    $accum{heartbeat}                 //= 60;
    $accum{extra_time}                //= 120;
    $accum{initial_journal_lookback}  //= 86460;
    $accum{journal_units}             //= 'ssh';
    $accum{bad_conn_patterns}         //= 'Failed password for invalid user,Failed password for root,Failed password for,Failed password for .* from,Failed password for .* from .* port';
    # never_block_cidrs should ALWAYS be defined in badips.conf - no hardcoded default
    # This prevents accidentally blocking trusted networks if config is missing
    $accum{never_block_cidrs}         //= '';
    $accum{db_dir}                    //= '/var/lib/bad_ips';
    $accum{db_file}                   //= '/var/lib/bad_ips/bad_ips.sql';
    $accum{log_level}                 //= 'INFO';   # honored by the app’s adapter, not here
    $accum{nft_table}                 //= 'inet';
    $accum{nft_family_table}          //= 'filter';
    $accum{nft_set}                   //= 'badipv4';
    $accum{file_sources}              //= '';
    $accum{max_file_tail_lines}       //= 2000;
    $accum{auto_mode}                 //= 1;

    # Normalize comma lists
    $accum{journal_units}     = _csv_to_array($accum{journal_units});
    $accum{bad_conn_patterns} = _csv_to_array($accum{bad_conn_patterns});
    $accum{never_block_cidrs} = _csv_to_array($accum{never_block_cidrs});
    $accum{file_sources}      = _csv_to_array($accum{file_sources});

    $self->{conf} = \%accum;

    # Phase 10: Add threading configuration defaults
    $self->{conf}->{ips_to_block_queue_max}                 //= 5000;
    $self->{conf}->{record_blocked_ip_queue_max}            //= 5000;
    $self->{conf}->{record_blocked_ip_queue_critical_time}  //= 300;
    $self->{conf}->{sync_to_central_db_queue_max}           //= 10000;
    $self->{conf}->{sync_to_central_db_queue_critical_time} //= 300;
    $self->{conf}->{central_db_batch_size}                  //= 1000;
    $self->{conf}->{central_db_batch_timeout}               //= 5;
    $self->{conf}->{pull_min_interval}                      //= 2;
    $self->{conf}->{pull_step_interval}                     //= 4;
    $self->{conf}->{pull_initial_interval}                  //= 20;
    $self->{conf}->{pull_max_interval}                      //= 180;
    $self->{conf}->{failover_log}                           //= '/var/lib/bad_ips/failover.log';
    $self->{conf}->{failover_enabled}                       //= 1;
    $self->{conf}->{graceful_shutdown_timeout}              //= 300;

    # PostgreSQL configuration defaults
    $self->{conf}->{db_type}                                //= 'postgresql';
    $self->{conf}->{db_host}                                //= '10.10.0.116';
    $self->{conf}->{db_port}                                //= 5432;
    $self->{conf}->{db_name}                                //= 'bad_ips';
    $self->{conf}->{db_user}                                //= 'bad_ips_hunter';
    $self->{conf}->{db_password}                            //= '';
    $self->{conf}->{db_ssl_mode}                            //= 'disable';
}

# Initialize thread-safe queues
sub _init_queues {
    my ($self) = @_;

    $ips_to_block_queue = Thread::Queue->new();
    $record_blocked_ip_queue = Thread::Queue->new();
    $sync_to_central_db_queue = Thread::Queue->new();

    $self->_log(debug => "Initialized thread-safe queues");
}

# Initialize central PostgreSQL database connection
sub _init_central_db {
    my ($self) = @_;

    return if $self->{dry_run};

    my $conf = $self->{conf};

    # Check if database is configured
    unless ($conf->{db_host} && $conf->{db_password}) {
        $self->_log(warn => "PostgreSQL not configured (missing db_host or db_password)");
        $self->_log(warn => "Central DB sync will be disabled");
        return;
    }

    my $dsn = sprintf(
        "dbi:Pg:dbname=%s;host=%s;port=%s;sslmode=%s",
        $conf->{db_name},
        $conf->{db_host},
        $conf->{db_port},
        $conf->{db_ssl_mode}
    );

    eval {
        $self->{central_dbh} = DBI->connect(
            $dsn,
            $conf->{db_user},
            $conf->{db_password},
            {
                RaiseError => 1,
                AutoCommit => 1,
                PrintError => 0,
            }
        );
        $self->_log(info => "Connected to PostgreSQL: $conf->{db_host}:$conf->{db_port}/$conf->{db_name}");
    };

    if ($@) {
        $self->_log(error => "Failed to connect to PostgreSQL: $@");
        $self->_log(warn => "Central DB sync will be disabled");
        $self->{central_dbh} = undef;
    }
}

# Helper: Create thread-local database connection
# Each thread must have its own DBI connection - handles cannot be shared
sub _create_thread_db_connection {
    my ($self) = @_;

    my $conf = $self->{conf};

    # Check if database is configured
    return undef unless $conf->{db_host} && $conf->{db_password};

    my $dsn = sprintf(
        "dbi:Pg:dbname=%s;host=%s;port=%s;sslmode=%s",
        $conf->{db_name},
        $conf->{db_host},
        $conf->{db_port},
        $conf->{db_ssl_mode}
    );

    my $dbh;
    eval {
        $dbh = DBI->connect(
            $dsn,
            $conf->{db_user},
            $conf->{db_password},
            {
                RaiseError => 1,
                AutoCommit => 1,
                PrintError => 0,
            }
        );
    };

    if ($@) {
        $self->_log(error => "Thread DB connection failed: $@");
        return undef;
    }

    return $dbh;
}

sub _load_detectors_from_confdir {
    my ($self) = @_;
    my $dir = $self->{conf_dir};
    my %detectors;

    return \%detectors unless defined $dir && -d $dir;

    opendir my $dh, $dir or do {
        $self->_log(warn => "Cannot open conf.d dir $dir");
        return \%detectors;
    };

    my @files = sort grep { /\.conf\z/ && -f File::Spec->catfile($dir, $_) } readdir $dh;
    closedir $dh;

    for my $file (@files) {
        my $path = File::Spec->catfile($dir, $file);
        my $cfg  = Config::Tiny->read($path) or next;

        # sections named detector:NAME or detector:NAME@HOST (also supports detector:NAME:HOST)
        for my $section (keys %$cfg) {
            next unless $section =~ /^detector:([^:\@]+)(?:\s*[\@:]\s*(.+))?$/i;
            my ($name, $host) = (lc $1, $2);
            my $h = $cfg->{$section} || {};

            # Arrays
            my $units_csv        = $h->{units}        // '';
            my $files_csv        = $h->{files}        // '';
            my $remote_files_csv = $h->{remote_files} // '';

            # Unique key per detector instance (name + optional host)
            my $key = defined $host ? "$name\@$host" : $name;

            $detectors{$key} ||= {
                name         => $name,
                host         => $host, # undef for local
                units        => [],
                files        => [],
                patterns     => [],
                remote_files => [],
            };

            push @{$detectors{$key}->{units}},         map { _trim($_) } grep { length } split(/\s*,\s*/, $units_csv);
            push @{$detectors{$key}->{files}},         map { _trim($_) } grep { length } split(/\s*,\s*/, $files_csv);
            push @{$detectors{$key}->{remote_files}},  map { _trim($_) } grep { length } split(/\s*,\s*/, $remote_files_csv);

            # Patterns: pattern1, pattern2...
            for my $k (sort keys %$h) {
                next unless $k =~ /^pattern\d+$/i;
                my $p = $h->{$k};
                next unless defined $p && length $p;
                push @{$detectors{$key}->{patterns}}, $p;
            }

            # Remote knobs (optional)
            $detectors{$key}->{remote_user}      = _trim($h->{remote_user})      if defined $h->{remote_user};
            $detectors{$key}->{remote_port}      = int($h->{remote_port})        if defined $h->{remote_port};
            $detectors{$key}->{remote_journald}  = ($h->{remote_journald} ? 1:0) if defined $h->{remote_journald};
            $detectors{$key}->{fetch_method}     = lc _trim($h->{fetch_method})  if defined $h->{fetch_method};
            $detectors{$key}->{fetch_interval}   = int($h->{fetch_interval} // 30);
            $detectors{$key}->{cache_dir}        = _trim($h->{cache_dir} // '/var/lib/bad_ips/remote');

            # Default method for remote files if not set
            if ($host && !$detectors{$key}->{fetch_method} && @{$detectors{$key}->{remote_files}}) {
                $detectors{$key}->{fetch_method} = 'scp';
            }
        }
    }

    # de-dup arrays
    for my $key (keys %detectors) {
        $detectors{$key}->{units}        = _dedup($detectors{$key}->{units});
        $detectors{$key}->{files}        = _dedup($detectors{$key}->{files});
        $detectors{$key}->{remote_files} = _dedup($detectors{$key}->{remote_files});
        $detectors{$key}->{patterns}     = _dedup($detectors{$key}->{patterns});
    }

    return \%detectors;
}

sub _dedup {
    my ($ary) = @_;
    my %seen; return [ grep { !$seen{$_}++ } @$ary ];
}

sub _trim {
    my ($s) = @_; $s //= ''; $s =~ s/^\s+|\s+$//g; return $s;
}

sub _auto_discover_sources {
    my ($self) = @_;
    return unless $self->{conf}->{auto_mode};

    my $detectors = $self->{detectors} || {};
    my @keys = sort keys %$detectors;
    unless (@keys) {
        $self->_log(info => "AUTO: no detectors defined; keeping static config");
        my @compiled = map { eval { qr/$_/ } || () } @{ $self->{conf}->{bad_conn_patterns} || [] };
        $self->{conf}->{compiled_patterns} = \@compiled;
        return;
    }

    # Running services list for LOCAL
    my %local_running;
    if (system("command -v systemctl >/dev/null 2>&1") == 0) {
        my $cmd = 'systemctl list-units --type=service --state=running --no-legend --no-pager';
        if (open my $fh, "-|", $cmd) {
            while (my $line = <$fh>) {
                $line =~ s/^\s+//;  # trim leading whitespace
                my ($unit) = split(/\s+/, $line, 2);
                $local_running{$unit} = 1 if $unit;
            }
            close $fh;
        }
    }

    my %exclude = map { $_ => 1 } @{ _csv_to_array($self->{conf}->{exclude_units} // '') };

    my (@journal_units, @file_sources);
    my %compiled;  # stringified re => re object

    DET: for my $key (@keys) {
        my $d = $detectors->{$key};
        my $is_remote = defined $d->{host} && length $d->{host};
        my @units = @{ $d->{units} || [] };

        # Compile patterns for this detector
        for my $p (@{ $d->{patterns} || [] }) {
            my $re = eval { qr/$p/ };
            if ($@) { $self->_log(warn => "Bad pattern in $key: $p ($@)"); next; }
            $compiled{"$re"} = $re;
        }

        if ($is_remote) {
            my $host = $d->{host};
            my $usr  = $d->{remote_user} ? "$d->{remote_user}@" : '';
            my $prt  = $d->{remote_port} ? "-p $d->{remote_port}" : '';

            # Remote journald availability: only if requested
            if ($d->{remote_journald} && @units) {
                my %r_running;
                my $cmd = sprintf "ssh -o BatchMode=yes %s %s%s 'systemctl list-units --type=service --state=running --no-legend --no-pager'",
                    $prt, $usr, $host;

                if ($self->{dry_run}) {
                    $self->_log(info => "[dry-run] would probe remote services: $cmd");
                    %r_running = map { $_ => 1 } @units; # pretend all running
                } else {
                    if (open my $fh, "-|", $cmd) {
                        while (my $line = <$fh>) {
                            $line =~ s/^\s+//;  # trim leading whitespace
                            my ($unit) = split(/\s+/, $line, 2);
                            $r_running{$unit} = 1 if $unit;
                        }
                        close $fh;
                    } else {
                        $self->_log(warn => "ssh probe failed for $key; skipping remote journald");
                        %r_running = ();
                    }
                }

                for my $u (@units) {
                    next if $exclude{$u};
                    next unless $u =~ /\.service\z/ ? $r_running{$u} : 1;
                    push @journal_units, "remote:$host:$u";
                }
            }

            # Remote file sources handled later by fetcher; nothing to add here
        } else {
            # Local detector: add units that are running or short aliases like "ssh"
            for my $u (@units) {
                next if $exclude{$u};
                next if $u =~ /\.service\z/ && !$local_running{$u};
                push @journal_units, $u;
            }
            push @file_sources, @{ $d->{files} || [] };
        }
    }

    # Merge static patterns too
    for my $s (@{ $self->{conf}->{bad_conn_patterns} || [] }) {
        my $re = eval { qr/$s/ }; $compiled{"$re"} = $re unless $@;
    }
    my @final_pats = map { $compiled{$_} } sort keys %compiled;

    # Commit sources
    $self->{conf}->{journal_units}      = _dedup(\@journal_units);
    $self->{conf}->{file_sources}       = _dedup(\@file_sources);
    $self->{conf}->{compiled_patterns}  = \@final_pats;

    my $units_msg = @journal_units ? join(", ", @journal_units) : "(none)";
    my $files_msg = @file_sources  ? join(", ", @file_sources)  : "(none)";
    $self->_log(info => "AUTO(detectors): units=$units_msg files=$files_msg patterns=" . scalar(@final_pats));
}

sub _csv_to_array {
    my ($s) = @_;
    return [] unless defined $s;
    my @x = map { my $t = $_; $t =~ s/^\s+|\s+$//g; $t } split(/\s*,\s*/, $s);
    return \@x;
}

sub _report_config {
    my ($self) = @_;
    my $c = $self->{conf};
    my $units = @{$c->{journal_units} || []} ? join(", ", @{$c->{journal_units}}) : '(none)';
    my $files = @{$c->{file_sources}  || []} ? join(", ", @{$c->{file_sources}})  : '(none)';
    my $pats  = $c->{compiled_patterns} && @{$c->{compiled_patterns}}
              ? scalar(@{$c->{compiled_patterns}})
              : scalar(@{$c->{bad_conn_patterns} || []});
    my @txt = qw/
        "bad_ips configuration:"
    /;
    push @txt, "  nft: table=$c->{nft_table} family_table=$c->{nft_family_table} set=$c->{nft_set}";
    push @txt, "  block_time=$c->{blocking_time}s sleep=$c->{sleep_time}s heartbeat=$c->{heartbeat}s";
    push @txt, "  journal_units: $units";
    push @txt, "  file_sources:  $files";
    push @txt, "  patterns:      $pats compiled";
    push @txt, "  db: $c->{db_file}";
    push @txt, "  log_level: $c->{log_level}";
    push @txt, "  auto_mode: @{[ $c->{auto_mode} ? 1 : 0 ]}";
    push @txt, "  dry_run:   @{[ $self->{dry_run} ? 1 : 0 ]}";
    my $txt = join("\n", @txt) . "\n";
    return $txt;
}

sub test_config {
    my ($self) = @_;
    # Re-run discovery + compile to be sure
    $self->_load_config();
    $self->{detectors} = $self->_load_detectors_from_confdir();
    $self->_auto_discover_sources();
    my $report = $self->_report_config();

    # Basic validations
    my @errs;
    push @errs, "Missing nft set name" unless $self->{conf}->{nft_set};
    push @errs, "No patterns compiled" unless ($self->{conf}->{compiled_patterns} && @{$self->{conf}->{compiled_patterns}});
    if (!@{$self->{conf}->{journal_units} || []} && !@{$self->{conf}->{file_sources} || []}) {
        push @errs, "No journald units or file sources configured/detected";
    }

    if (@errs) {
        $report .= "\nErrors:\n  - " . join("\n  - ", @errs) . "\n";
        return (0, "invalid", $report);
    } else {
        $report .= "\nStatus: OK\n";
        return (1, "ok", $report);
    }
}

# -------------------- DB --------------------
sub _init_db {
    my ($self) = @_;
    my $dir = $self->{conf}->{db_dir};
    unless (-d $dir) {
        make_path($dir, { mode => 0755 }) or die "Failed to create $dir: $!";
        $self->_log(info => "Created $dir");
    }

    my $dbf = $self->{conf}->{db_file};
    my $dbh = DBI->connect("dbi:SQLite:dbname=$dbf","","", {
        RaiseError => 1,
        AutoCommit => 1,
        sqlite_use_immediate_transaction => 1,
    }) or die "SQLite connect failed: $DBI::errstr";

    $dbh->do('PRAGMA journal_mode=WAL');
    $dbh->do('PRAGMA synchronous=NORMAL');

    $dbh->do(q{
        CREATE TABLE IF NOT EXISTS jailed_ips (
            ip               TEXT PRIMARY KEY,
            first_jailed_at  INTEGER NOT NULL,
            last_jailed_at   INTEGER NOT NULL,
            expires_at       INTEGER NOT NULL,
            count            INTEGER NOT NULL DEFAULT 1
        )
    });

    # Phase 9: New tables for block tracking and propagation visibility
    $dbh->do(q{
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
    });

    $dbh->do(q{
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
    });

    $dbh->do(q{
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            upgraded_at INTEGER NOT NULL
        )
    });

    # Create indexes for new tables
    $dbh->do(q{CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires ON blocked_ips(expires_at)});
    $dbh->do(q{CREATE INDEX IF NOT EXISTS idx_blocked_ips_service ON blocked_ips(originating_service)});
    $dbh->do(q{CREATE INDEX IF NOT EXISTS idx_blocked_ips_server ON blocked_ips(originating_server)});
    $dbh->do(q{CREATE INDEX IF NOT EXISTS idx_propagation_status ON propagation_status(status)});
    $dbh->do(q{CREATE INDEX IF NOT EXISTS idx_propagation_pending ON propagation_status(status, last_attempt)});

    # Set schema version to 2 if not already set
    my ($current_version) = $dbh->selectrow_array("SELECT version FROM schema_version LIMIT 1");
    unless ($current_version) {
        $dbh->do("INSERT INTO schema_version (version, upgraded_at) VALUES (2, ?)", undef, time());
    }

    $self->{dbh} = $dbh;

    # cache the UPSERT statement
    $self->{sth_upsert} = $dbh->prepare(q{
        INSERT INTO jailed_ips (ip, first_jailed_at, last_jailed_at, expires_at, count)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(ip) DO UPDATE SET
            last_jailed_at = excluded.last_jailed_at,
            expires_at     = excluded.expires_at,
            count          = jailed_ips.count + 1
    });

    $self->_log(info => "SQLite ready at $dbf");
}

sub _db_upsert_jailed_ip {
    my ($self, $ip, $expires_epoch) = @_;
    my $now = int(time());
    $self->{sth_upsert}->execute($ip, $now, $now, int($expires_epoch));
}

sub _db_upsert_blocked_ip {
    my ($self, $ip, $expires_epoch, $metadata) = @_;
    my $now = int(time());
    my $hostname = $self->{conf}->{hostname} || `hostname -s`;
    chomp $hostname;

    # Extract metadata with defaults
    my $service = $metadata->{service} || 'unknown';
    my $detector = $metadata->{detector} || 'unknown';
    my $pattern = $metadata->{pattern} || 'unknown';
    my $log_line = $metadata->{log_line} || '';

    # Truncate log line to 500 chars
    $log_line = substr($log_line, 0, 500) if length($log_line) > 500;

    # UPSERT into blocked_ips table
    my $sql = q{
        INSERT INTO blocked_ips (
            ip, originating_server, originating_service, detector_name,
            pattern_matched, matched_log_line,
            first_blocked_at, last_seen_at, expires_at, block_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(ip, originating_server) DO UPDATE SET
            last_seen_at = excluded.last_seen_at,
            expires_at = excluded.expires_at,
            block_count = blocked_ips.block_count + 1,
            pattern_matched = excluded.pattern_matched,
            matched_log_line = excluded.matched_log_line
    };

    eval {
        $self->{dbh}->do($sql, undef,
            $ip, $hostname, $service, $detector,
            $pattern, $log_line,
            $now, $now, int($expires_epoch)
        );
    };
    if ($@) {
        $self->_log(error => "Failed to insert into blocked_ips for $ip: $@");
    }
}

# -------------------- main loop --------------------
sub run {
    my ($self) = @_;

    $self->_log(info => "Starting Bad IPs monitoring");
    return $self->run_hunter();
}

# ==================== PHASE 10: THREAD FUNCTIONS ====================

# Thread: nft_blocker_thread
# CRITICAL: This thread must NEVER block on I/O
# Purpose: Pop from ips_to_block_queue, add to nftables, push to record_blocked_ip_queue
sub nft_blocker_thread {
    my ($self) = @_;
    $self->_log(info => "nft_blocker_thread started");

    my $set = $self->{conf}->{nft_set};
    my $tab = $self->{conf}->{nft_family_table};
    my $fam = $self->{conf}->{nft_table};
    my $ttl = $self->{conf}->{blocking_time};

    while (!$shutdown) {
        # Non-blocking dequeue with 1 second timeout
        my $item = $ips_to_block_queue->dequeue_timed(1);
        next unless $item;

        my $ip = $item->{ip};
        my $source = $item->{source} || 'unknown';
        my $detector = $item->{detector} || 'unknown';
        my $log_line = $item->{line};

        # Skip if already blocked
        if (exists $self->{blocked}{$ip}) {
            next;
        }

        # Check never_block_cidrs
        if ($self->_is_never_block_ip($ip)) {
            $self->_log(debug => "Skipping never-block IP: $ip");
            next;
        }

        # Execute nft command (FAST - no I/O wait!)
        my $cmd = "nft add element $fam $tab $set { $ip timeout ${ttl}s }";

        if ($self->{dry_run}) {
            $self->_log(info => "[dry-run] would jail $ip for ${ttl}s");
            my $exp = time() + $ttl;
            $self->{blocked}{$ip} = $exp;

            # Even in dry-run, queue for recording
            $record_blocked_ip_queue->enqueue({
                ip => $ip,
                expires_at => $exp,
                source => $source,
                detector => $detector,
                log_line => $log_line,
            });
            next;
        }

        # Execute nft command
        if (system($cmd) == 0) {
            my $exp = time() + $ttl;
            $self->{blocked}{$ip} = $exp;

            $self->_log(info => "Jailed $ip for ${ttl}s (source: $source, detector: $detector)");

            # Enqueue for database recording (async)
            $record_blocked_ip_queue->enqueue({
                ip => $ip,
                expires_at => $exp,
                source => $source,
                detector => $detector,
                log_line => $log_line,
            });
        } else {
            $self->_log(error => "nft add failed for $ip: $!");
        }
    }

    $self->_log(info => "nft_blocker_thread shutting down");
}

# Helper: Check if IP is in never_block_cidrs
sub _is_never_block_ip {
    my ($self, $ip) = @_;
    my $cidrs = $self->{conf}->{never_block_cidrs} || [];
    return 0 unless @$cidrs;
    return cidrlookup($ip, @$cidrs);
}

# Thread: local_db_recorder_thread
# Purpose: Pop from record_blocked_ip_queue, write to local SQLite, push to sync_to_central_db_queue
sub local_db_recorder_thread {
    my ($self) = @_;
    $self->_log(info => "local_db_recorder_thread started");

    while (!$shutdown || $record_blocked_ip_queue->pending() > 0) {
        my $item = $record_blocked_ip_queue->dequeue_timed(1);
        next unless $item;

        my $ip = $item->{ip};
        my $exp = $item->{expires_at};

        # Write to local SQLite (blocking I/O is acceptable here)
        eval {
            $self->_db_upsert_jailed_ip($ip, $exp);
            $self->_db_upsert_blocked_ip($ip, $exp, {
                service => $item->{source},
                detector => $item->{detector},
            });
        };
        if ($@) {
            $self->_log(error => "Local DB upsert failed for $ip: $@");
        }

        # Enqueue for central DB sync
        $sync_to_central_db_queue->enqueue($item);
    }

    $self->_log(info => "local_db_recorder_thread shutting down (drained queue)");
}

# Thread: central_db_sync_thread
# Purpose: Pop from sync_to_central_db_queue (batched), write to PostgreSQL
sub central_db_sync_thread {
    my ($self) = @_;
    $self->_log(info => "central_db_sync_thread started");

    # Create thread-local database connection
    my $thread_dbh = $self->_create_thread_db_connection();
    unless ($thread_dbh) {
        $self->_log(warn => "central_db_sync_thread: no database connection, exiting");
        return;
    }
    $self->_log(info => "central_db_sync_thread: established thread-local DB connection");

    my $batch_size = $self->{conf}->{central_db_batch_size};
    my $queue_max = $self->{conf}->{sync_to_central_db_queue_max};
    my $critical_time = $self->{conf}->{sync_to_central_db_queue_critical_time};
    my $hostname = hostname();

    while (!$shutdown || $sync_to_central_db_queue->pending() > 0) {
        my $queue_size = $sync_to_central_db_queue->pending();

        # Check for critical queue overflow
        if ($queue_size > $queue_max) {
            $self->{queue_exceeded_start}{central_db} ||= time();
            my $exceeded_duration = time() - $self->{queue_exceeded_start}{central_db};

            if ($exceeded_duration > $critical_time) {
                $self->_log(error => "CRITICAL: Central DB queue exceeded $queue_max for ${exceeded_duration}s, failing over to disk");

                # Drain to failover log
                my $drained = 0;
                while (my $item = $sync_to_central_db_queue->dequeue_nb()) {
                    $self->_append_to_failover_log($item) or $self->_log(warn => "Cannot write failover log, dropping IP: $item->{ip}");
                    $drained++;
                }

                $self->_log(warn => "Drained $drained items to failover log");
                $self->{queue_exceeded_start}{central_db} = 0;
                sleep 60;  # Back off
                next;
            }
        } else {
            $self->{queue_exceeded_start}{central_db} = 0;
        }

        # Collect batch
        my @batch;
        my $timeout = 1;
        while (@batch < $batch_size) {
            my $item = $sync_to_central_db_queue->dequeue_timed($timeout);
            last unless $item;
            push @batch, $item;
            $timeout = 0;  # After first item, don't wait
        }

        next unless @batch;

        # Batch INSERT to PostgreSQL
        eval {
            for my $item (@batch) {
                my $sth = $thread_dbh->prepare(
                    "SELECT record_blocked_ip(?, ?, ?, NOW() + INTERVAL '? seconds', ?)"
                );
                $sth->execute(
                    $hostname,
                    $item->{ip},
                    $item->{detector},
                    $self->{conf}->{blocking_time},
                    $item->{log_line}
                );
            }
        };

        if ($@) {
            $self->_log(error => "Central DB batch INSERT failed: $@, requeueing " . scalar(@batch) . " items");
            $sync_to_central_db_queue->enqueue($_) for @batch;
            sleep 10;  # Back off
        } else {
            $self->_log(debug => "Synced " . scalar(@batch) . " IPs to central DB");
        }
    }

    # Close thread-local connection
    $thread_dbh->disconnect() if $thread_dbh;
    $self->_log(info => "central_db_sync_thread shutting down (drained queue)");
}

# Helper: Append to failover log
sub _append_to_failover_log {
    my ($self, $item) = @_;
    my $log_file = $self->{conf}->{failover_log};

    return 0 unless $self->{conf}->{failover_enabled};

    eval {
        open my $fh, '>>', $log_file or die $!;
        print $fh join("\t",
            time(),
            hostname(),
            $item->{ip},
            $item->{source},
            $item->{detector}
        ) . "\n";
        close $fh;
        1;
    } or do {
        $self->_log(error => "Failed to write failover log: $@");
        return 0;
    };

    return 1;
}

# Thread: pull_global_blocks_thread
# Purpose: Query central DB for new blocks, push to ips_to_block_queue (adaptive interval)
sub pull_global_blocks_thread {
    my ($self) = @_;
    $self->_log(info => "pull_global_blocks_thread started");

    # Create thread-local database connection
    my $thread_dbh = $self->_create_thread_db_connection();
    unless ($thread_dbh) {
        $self->_log(warn => "pull_global_blocks_thread: no database connection, exiting");
        return;
    }
    $self->_log(info => "pull_global_blocks_thread: established thread-local DB connection");

    my $min_interval = $self->{conf}->{pull_min_interval};
    my $current_interval = $self->{conf}->{pull_initial_interval};
    my $max_interval = $self->{conf}->{pull_max_interval};
    my $step = $self->{conf}->{pull_step_interval};
    my $last_check_time = time();

    while (!$shutdown) {
        sleep $current_interval;
        last if $shutdown;

        my $new_blocks_found = 0;

        # Query central DB for new blocks
        eval {
            my $hostname = hostname();
            my $sth = $thread_dbh->prepare(
                "SELECT subnet, hostname, service_name, detector_name
                 FROM active_blocks
                 WHERE hostname != ?
                 AND detected_at > TO_TIMESTAMP(?)"
            );
            $sth->execute($hostname, $last_check_time);

            while (my $row = $sth->fetchrow_hashref) {
                $new_blocks_found++;

                # Enqueue for blocking
                $ips_to_block_queue->enqueue({
                    ip => $row->{subnet},
                    source => "central_db:$row->{hostname}",
                    detector => $row->{detector_name} || 'global_sync',
                    line => undef,
                });
            }

            $last_check_time = time();
        };

        if ($@) {
            $self->_log(error => "Failed to pull global blocks: $@");
            sleep 10;  # Back off on error
            next;
        }

        if ($new_blocks_found > 0) {
            $self->_log(info => "Pulled $new_blocks_found new blocks from central DB");
        }

        # Adaptive interval adjustment
        if ($new_blocks_found > 0) {
            $current_interval -= $step if ($current_interval - $step >= $min_interval);
            $self->_log(debug => "Pull interval decreased to ${current_interval}s (found new blocks)");
        } else {
            $current_interval += $step if ($current_interval + $step <= $max_interval);
            $self->_log(debug => "Pull interval increased to ${current_interval}s (no new blocks)");
        }
    }

    # Close thread-local connection
    $thread_dbh->disconnect() if $thread_dbh;
    $self->_log(info => "pull_global_blocks_thread shutting down");
}

# Thread: log_watcher_thread (generic)
# Purpose: Watch logs (file or journalctl), find bad IPs, push to ips_to_block_queue
# Note: Phase 10 uses existing _read_all_sources() in main thread for now
# TODO Phase 10.1: Refactor into per-detector threads with proper file position tracking
sub log_watcher_thread {
    my ($self, $detector_name, $detector_config) = @_;
    $self->_log(info => "log_watcher_thread started for detector: $detector_name");

    # This is a placeholder for future per-detector threading
    # For Phase 10, we'll continue using the existing _read_all_sources() approach
    # in the main run_hunter loop, but enqueue to ips_to_block_queue

    $self->_log(warn => "Per-detector log watcher threads not yet implemented in Phase 10");
    $self->_log(info => "log_watcher_thread shutting down");
}

# Graceful shutdown handler
sub _shutdown_gracefully {
    my ($self, $signal) = @_;
    $self->_log(info => "Received $signal, initiating graceful shutdown");

    {
        lock($shutdown);
        $shutdown = 1;
        $shutdown_start_time = time();
    }

    my $timeout = $self->{conf}->{graceful_shutdown_timeout};
    $self->_log(info => "Allowing ${timeout}s for threads to drain queues");

    # Main thread will handle joining worker threads
}

sub run_hunter {
    my ($self) = @_;
    $self->_log(info => "Starting main thread to find and block bad IPs");

    # Setup signal handlers for graceful shutdown
    $SIG{QUIT} = sub { $self->_shutdown_gracefully("SIGQUIT"); };
    $SIG{INT}  = sub { $self->_shutdown_gracefully("SIGINT"); };
    $SIG{TERM} = sub { $self->_shutdown_gracefully("SIGTERM"); };
    $SIG{HUP}  = sub { $self->_reload_config_signal(); };

    # Start worker threads
    $self->_log(info => "Starting worker threads...");

    $self->_log(debug => "Starting nft_blocker_thread");
    push @{$self->{threads}}, threads->create(sub { $self->nft_blocker_thread() });
    $self->_log(debug => "Starting local_db_recorder_thread");
    push @{$self->{threads}}, threads->create(sub { $self->local_db_recorder_thread() });
    $self->_log(debug => "Starting central_db_sync_thread");
    push @{$self->{threads}}, threads->create(sub { $self->central_db_sync_thread() });
    $self->_log(debug => "Starting pull_global_blocks_thread");
    push @{$self->{threads}}, threads->create(sub { $self->pull_global_blocks_thread() });

    $self->_log(info => "All worker threads started");

    # Main loop: Read logs and enqueue IPs for blocking
    my $hb_at = time() + $self->{conf}->{heartbeat};
    my %new_since_hb;

    # Initial log read
    my $entries = $self->_read_all_sources(
        journal_lookback => $self->{conf}->{initial_journal_lookback},
        max_file_lines   => $self->{conf}->{max_file_tail_lines},
    );

    while (!$shutdown) {
        $self->{run_count}++;
        $self->_log(debug => "Run #$self->{run_count}: processing log entries");

        # Process log entries
        my $bad = $self->_bad_entries($entries);
        my $ip_data = $self->_remote_addresses($bad);

        # Enqueue IPs (nft_blocker_thread will check never_block_cidrs)
        for my $item (@$ip_data) {
            $ips_to_block_queue->enqueue({
                ip => $item->{ip},
                source => $item->{metadata}->{service} || 'unknown',
                detector => $item->{metadata}->{detector} || 'unknown',
                line => $item->{metadata}->{log_line},
            });
            $new_since_hb{$item->{ip}} = 1;
        }

        $self->_log(debug => "Run #$self->{run_count}: enqueued " . scalar(@$ip_data) . " IPs for blocking");

        sleep $self->{conf}->{sleep_time};
        $self->_remove_expired_ips();

        # Heartbeat
        if (time() > $hb_at) {
            $hb_at = time() + $self->{conf}->{heartbeat};
            $self->_reload_blocked_ips();

            my @sorted = sort { $self->{blocked}{$a} <=> $self->{blocked}{$b} } keys %{$self->{blocked}};
            my @new_ips = sort { $a cmp $b } keys %new_since_hb;

            $self->_log(info => "Heartbeat: Total blocked IPs: " . scalar(@sorted));
            $self->_log(info => "Run count: $self->{run_count}");
            $self->_log(info => "Queue depths: ips_to_block=" . $ips_to_block_queue->pending() .
                               ", record=" . $record_blocked_ip_queue->pending() .
                               ", sync=" . $sync_to_central_db_queue->pending());

            if (@new_ips) {
                $self->_log(info => "Newly blocked since last heartbeat (" . scalar(@new_ips) . "): " . join(", ", @new_ips));
            } else {
                $self->_log(info => "No new IPs since last heartbeat");
            }
            %new_since_hb = ();
        }

        # Re-read logs
        $entries = $self->_read_all_sources(
            journal_lookback => $self->{conf}->{initial_journal_lookback},
            max_file_lines   => $self->{conf}->{max_file_tail_lines},
        );
    }

    # Shutdown: wait for threads to complete
    $self->_log(info => "Main loop exiting, waiting for threads to drain queues...");
    for my $thr (@{$self->{threads}}) {
        $thr->join();
    }
    $self->_log(info => "All threads joined, exiting");
}

# -------------------- Read All Sources --------------------
sub _read_all_sources {
    my ($self, %args) = @_;
    my $jl  = $args{journal_lookback} // 300;
    my $max = $args{max_file_lines}   // 2000;

    # 1) journald units
    my $entries = $self->_read_journals($jl);

    # 2) file sources
    my $files = $self->{conf}->{file_sources} || [];
    if (@$files) {
        my $file_entries = $self->_read_files_recent($files, $max);
        for my $unit (keys %$file_entries) {
            $entries->{$unit} = $file_entries->{$unit};
        }
        $self->_log(debug => "Merged file sources: " . join(", ", @$files));
    }

    return $entries;
}

# -------------------- Read Files --------------------
sub _read_files_recent {
    my ($self, $files, $max_lines) = @_;
    my %by_unit;  # "file:/path" => { pidish => msg|msg|... }

    FILE: for my $path (@$files) {
        next FILE unless defined $path && -r $path;

        my $unit_key = "file:$path";
        my $count = 0;

        my $bw = File::ReadBackwards->new($path);
        unless ($bw) {
            $self->_log(warn => "Could not open $path for backward read");
            next FILE;
        }

        while (defined(my $line = $bw->readline)) {
            last if $count++ >= ($max_lines // 2000);
            chomp $line;
            next unless $line =~ /\d{1,3}(?:\.\d{1,3}){3}/;

            my $pidish = "$unit_key:$count";
            if (exists $by_unit{$unit_key}{$pidish}) {
                $by_unit{$unit_key}{$pidish} .= "|$line";
            } else {
                $by_unit{$unit_key}{$pidish}  = $line;
            }
        }
    }

    return \%by_unit;
}

# -------------------- journald --------------------
sub _read_journals {
    my ($self, $lookback) = @_;
    my $entries = {};
    my $units = $self->{conf}->{journal_units} || [];
    for my $unit (@$units) {
        $self->_log(debug => "Reading journal for unit $unit back $lookback seconds");
        my $u = $self->_read_journal_unit($unit, $lookback);
        $self->_log(debug => "Found " . scalar(keys %$u) . " entries with IPv4s in unit $unit");
        $entries->{$unit} = $u;
    }
    return $entries;
}

sub _read_journal_unit {
    my ($self, $unit, $lookback) = @_;
    my $entries = {};
    my $cmd = qq(journalctl --since='$lookback seconds ago' --unit=$unit);
    open my $fh, "-|", $cmd or die $!;
    while (my $line = <$fh>) {
        chomp $line;
        my @sl = split(' ', $line, 6);
        my $threadid = $sl[4] || "no-thread";
        my $msg      = $sl[5] || "no message";
        $entries->{$threadid} = defined $entries->{$threadid} ? "$entries->{$threadid}|$msg" : $msg;
    }
    close $fh;

    # filter only lines containing IPv4
    for my $k (keys %$entries) {
        delete $entries->{$k} unless $entries->{$k} =~ /\d{1,3}(?:\.\d{1,3}){3}/;
    }
    return $entries;
}

sub _bad_entries {
    my ($self, $entries) = @_;
    my %bad = ();
    my $patterns = $self->{conf}->{compiled_patterns}
        ? $self->{conf}->{compiled_patterns}
        : [ map { qr/$_/ } @{ $self->{conf}->{bad_conn_patterns} } ];

    my $total_entries = 0;
    for my $unit (keys %$entries) {
        $total_entries += scalar(keys %{$entries->{$unit}});
    }
    $self->_log(debug => "Checking $total_entries log entries against " . scalar(@$patterns) . " patterns");

    for my $unit (keys %$entries) {
        my $u = $entries->{$unit};
        $self->_log(debug => "Processing unit: $unit (" . scalar(keys %$u) . " entries)");
        ENTRY: for my $pid (keys %$u) {
            my $msg = $u->{$pid};
            my $pattern_num = 0;
            for my $re (@$patterns) {
                $pattern_num++;
                if ($msg =~ $re) {
                    # Store message with metadata
                    $bad{$pid} = {
                        msg => $msg,
                        unit => $unit,
                        pattern_num => $pattern_num,
                        pattern => $self->{conf}->{bad_conn_patterns}->[$pattern_num-1] || 'unknown',
                        detector => $self->_detector_name_from_unit($unit),
                        service => $self->_service_name_from_unit($unit)
                    };
                    $self->_log(debug => "Unit $unit matched pattern#$pattern_num: '" . $self->{conf}->{bad_conn_patterns}->[$pattern_num-1] . "'");
                    $self->_log(debug => "Matched log line: " . substr($msg, 0, 100) . (length($msg) > 100 ? "..." : ""));
                    last ENTRY;
                }
            }
        }
    }
    $self->_log(debug => "Found " . scalar(keys %bad) . " bad entries");
    return \%bad;
}

sub _detector_name_from_unit {
    my ($self, $unit) = @_;
    # Extract detector name from unit name
    # e.g., "sshd.service" -> "sshd", "nginx.service" -> "nginx"
    return 'file' if $unit =~ /^file:/;
    my ($name) = $unit =~ /^([^\.]+)/;
    return $name || 'unknown';
}

sub _service_name_from_unit {
    my ($self, $unit) = @_;
    # Map unit names to service names
    return 'file' if $unit =~ /^file:/;
    my ($name) = $unit =~ /^([^\.]+)/;
    return $name || 'unknown';
}

sub _remote_addresses {
    my ($self, $entries) = @_;
    my %ip_metadata = (); # ip => metadata

    $self->_log(debug => "Extracting IPs from " . scalar(keys %$entries) . " bad entries");

    for my $k (keys %$entries) {
        my $entry = $entries->{$k};
        my $msg = ref($entry) eq 'HASH' ? $entry->{msg} : $entry;

        # Extract all IPs from this message
        my @found_ips;
        while ($msg =~ /$RE{net}{IPv4}/g) {
            push @found_ips, $&;
        }

        $self->_log(debug => "Extracted " . scalar(@found_ips) . " IPs from log entry") if @found_ips;

        # Store first IP found with its metadata
        if (@found_ips && ref($entry) eq 'HASH') {
            for my $ip (@found_ips) {
                unless (exists $ip_metadata{$ip}) {
                    $ip_metadata{$ip} = {
                        service => $entry->{service},
                        detector => $entry->{detector},
                        pattern => "pattern$entry->{pattern_num}: $entry->{pattern}",
                        log_line => $entry->{msg}
                    };
                    $self->_log(debug => "Found IP $ip from detector '$entry->{detector}'");
                }
            }
        } elsif (@found_ips) {
            # Fallback for old format (no metadata)
            for my $ip (@found_ips) {
                $ip_metadata{$ip} ||= {};
            }
        }
    }

    my @ips = sort { $a cmp $b } keys %ip_metadata;
    if (@ips) {
        $self->_log(debug => "Extracted " . scalar(@ips) . " unique IPs: " . join(", ", @ips));
    } else {
        $self->_log(debug => "No IPs extracted from bad entries");
    }

    # Return array ref of hashrefs: [ { ip => '1.2.3.4', metadata => {...} }, ... ]
    return [ map { { ip => $_, metadata => $ip_metadata{$_} } } @ips ];
}

sub _remove_never_block_ips {
    my ($self, $ip_data) = @_;
    my @kept;

    for my $item (@$ip_data) {
        my $ip = $item->{ip};
        my $should_block = 1;

        for my $cidr (@{$self->{conf}->{never_block_cidrs}}) {
            if (cidrlookup($ip, $cidr)) {
                $self->_log(info => "IP $ip is in $cidr; skipping");
                $should_block = 0;
                last;
            }
        }

        push @kept, $item if $should_block;
    }

    return \@kept;
}

sub _remove_already_blocked_ips {
    my ($self, $ip_data) = @_;
    my @new_blocks;
    my @already;

    for my $item (@$ip_data) {
        my $ip = $item->{ip};
        if ($self->{blocked}{$ip}) {
            push @already, $ip;
        } else {
            push @new_blocks, $item;
        }
    }

    $self->_log(debug => "Already blocked: " . join(',', @already)) if @already;
    return \@new_blocks;
}

# -------------------- nftables --------------------
sub _add_ips_to_nft {
    my ($self, $ip_data) = @_;
    my $set   = $self->{conf}->{nft_set};
    my $tab   = $self->{conf}->{nft_family_table};
    my $fam   = $self->{conf}->{nft_table};
    my $ttl   = $self->{conf}->{blocking_time};

    # Sort by IP address
    my @sorted = sort { $a->{ip} cmp $b->{ip} } @$ip_data;

    for my $item (@sorted) {
        my $ip = $item->{ip};
        my $metadata = $item->{metadata} || {};
        my $cmd = "nft add element $fam $tab $set { $ip timeout ${ttl}s }";

        if ($self->{dry_run}) {
            $self->_log(info => "[dry-run] would jail $ip for ${ttl}s with: $cmd");
            my $exp = time() + $ttl;
            $self->{blocked}{$ip} = $exp;
            next; # do not touch DB in dry-run
        }

        if (system($cmd) == 0) {
            my $exp = time() + $ttl;
            $self->{blocked}{$ip} = $exp;

            # Insert into both old and new tables (dual-write)
            eval { $self->_db_upsert_jailed_ip($ip, $exp) };
            $@ and $self->_log(error => "SQLite upsert (jailed_ips) failed for $ip: $@");

            eval { $self->_db_upsert_blocked_ip($ip, $exp, $metadata) };
            $@ and $self->_log(error => "SQLite upsert (blocked_ips) failed for $ip: $@");

            my $svc = $metadata->{service} || 'unknown';
            my $det = $metadata->{detector} || 'unknown';
            $self->_log(info  => "Jailed $ip for ${ttl}s (service: $svc, detector: $det)");
        } else {
            my $err = $!;
            $self->_log(error => "nft add failed for $ip: $err");
        }
    }
}

sub _remove_expired_ips {
    my ($self) = @_;
    my $now = time();
    for my $ip (keys %{$self->{blocked}}) {
        if ($now > $self->{blocked}{$ip}) {
            $self->_log(info => "Parolling $ip from in-memory cache");
            delete $self->{blocked}{$ip};
        }
    }
}

sub _reload_blocked_ips {
    my ($self) = @_;
    $self->{blocked} = {};
    $self->_initial_load_blocked_ips();
}

sub _initial_load_blocked_ips {
    my ($self) = @_;
    my $json = $self->_nft_as_json();
    for my $item (@{$json->{nftables}}) {
        next unless exists $item->{set}->{name} && $item->{set}->{name} eq $self->{conf}->{nft_set};
        for my $elem (@{$item->{set}->{elem}}) {
            my $ip      = $elem->{elem}->{val};
            my $expires = $elem->{elem}->{expires} + time();
            $self->{blocked}{$ip} = $expires;
            eval { $self->_db_upsert_jailed_ip($ip, $expires) };
            $@ and $self->_log(error => "SQLite sync failed for $ip: $@");
        }
    }
}

sub _nft_as_json {
    my ($self) = @_;
    my $out = `nft -j list ruleset`;
    return decode_json($out);
}

# -------------------- signal handlers --------------------
sub _reload_config_signal {
    my ($self) = @_;
    eval {
        $self->_log(info => "SIGHUP received: reloading configuration");
        $self->_load_config();
        $self->{detectors} = $self->_load_detectors_from_confdir();
        $self->_auto_discover_sources();
        $self->_log(info => "New config:\n" . $self->_report_config());
    };
    if ($@) {
        $self->_log(error => "Failed to reload config on SIGHUP: $@");
    }
}

# -------------------- tiny logger shim --------------------
sub _log {
    my ($self, $lvl, $msg) = @_;
    $lvl ||= 'info';
    my $meth = $log->can($lvl) ? $lvl : 'info';
    $log->$meth($msg);
}

1;
