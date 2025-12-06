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
use Log::Any qw($log);
use Regexp::Common qw(net);
use Net::CIDR qw(cidrlookup);
use Sys::Hostname qw(hostname);
use File::ReadBackwards;

our $VERSION = '0.01';

# Service -> how to read + patterns (moved to conf.d, kept empty here)
my %DETECTORS = ();

sub new {
    my ($class, %args) = @_;

    my $self = {
        conf_main  => $args{conf_main} // '/usr/local/etc/badips.conf',
        conf_dir   => $args{conf_dir}  // '/usr/local/etc/badips.d',
        conf       => {},
        dbh        => undef,
        sth_upsert => undef,
        blocked    => {},   # ip => epoch_expires
        run_count  => 0,
        dry_run    => $args{dry_run} ? 1 : 0,
        remote_state => {}, # for future remote fetch cadence
    };

    bless $self, $class;
    $self->_load_config();
    $self->{detectors} = $self->_load_detectors_from_confdir();
    $self->_auto_discover_sources();   # compiles patterns + sources
    $self->_init_db();
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

    # Check mode and dispatch
    my $mode = $self->{conf}->{mode} || 'hunter';

    if ($mode eq 'gatherer') {
        $self->_log(info => "Starting in gatherer mode");
        return $self->run_gatherer();
    } else {
        $self->_log(info => "Starting in hunter mode");
        return $self->run_hunter();
    }
}

sub run_hunter {
    my ($self) = @_;
    my $hb_at = time() + $self->{conf}->{heartbeat};

    my $entries = $self->_read_all_sources(
        journal_lookback => $self->{conf}->{initial_journal_lookback},
        max_file_lines   => $self->{conf}->{max_file_tail_lines},
    );
    for my $unit (keys %$entries) {
        my $cnt = scalar keys %{$entries->{$unit}};
        $self->_log(debug => "Source $unit yielded $cnt items with IPv4s");
    }
    my %new_since_hb;

    $SIG{QUIT} = sub { $self->_log(info => "SIGQUIT"); exit 0; };
    $SIG{INT}  = sub { $self->_log(info => "SIGINT");  exit 0; };
    $SIG{TERM} = sub { $self->_log(info => "SIGTERM"); exit 0; };
    $SIG{HUP}  = sub { $self->_reload_config_signal(); };

    while (1) {
        $self->{run_count}++;

        my $bad = $self->_bad_entries($entries);
        my $ip_data = $self->_remote_addresses($bad);
        $ip_data    = $self->_remove_never_block_ips($ip_data);
        $ip_data    = $self->_remove_already_blocked_ips($ip_data);

        # Track IPs for heartbeat reporting
        map { $new_since_hb{$_->{ip}} = 1 } @$ip_data if @$ip_data;

        $self->_add_ips_to_nft($ip_data);
        $self->_log(debug => "Run #$self->{run_count}: blocked " . scalar(@$ip_data) . " new IPs");

        sleep $self->{conf}->{sleep_time};
        $self->_remove_expired_ips();

        if (time() > $hb_at) {
            $hb_at = time() + $self->{conf}->{heartbeat};
            $self->_reload_blocked_ips();
            $self->_log(info => "Heartbeat");
            my @sorted = sort { $self->{blocked}{$a} <=> $self->{blocked}{$b} } keys %{$self->{blocked}};
            $self->_log(debug => "Blocked IPs: " . join(", ", @sorted)) if @sorted;
            $self->_log(info  => "Total blocked IPs: " . scalar(@sorted));
            $self->_log(info  => "Have ran $self->{run_count} times.");
            my @new_ips = sort { $a cmp $b } keys %new_since_hb;
            if (@new_ips) {
                $self->_log(info => "Newly blocked since last heartbeat: " . join(", ", @new_ips));
            } else {
                $self->_log(info => "No new IPs since last heartbeat.");
            }
            %new_since_hb = ();
        }

        $entries = $self->_read_all_sources(
            journal_lookback => $self->{conf}->{initial_journal_lookback},
            max_file_lines   => $self->{conf}->{max_file_tail_lines},
        );
        for my $unit (keys %$entries) {
            my $cnt = scalar keys %{$entries->{$unit}};
            $self->_log(debug => "Source $unit yielded $cnt items with IPv4s");
        }
    }
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

    for my $unit (keys %$entries) {
        my $u = $entries->{$unit};
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
                    $self->_log(debug => "Unit $unit matched pattern#$pattern_num");
                    last ENTRY;
                }
            }
        }
    }
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

    for my $k (keys %$entries) {
        my $entry = $entries->{$k};
        my $msg = ref($entry) eq 'HASH' ? $entry->{msg} : $entry;

        # Extract all IPs from this message
        my @found_ips;
        while ($msg =~ /$RE{net}{IPv4}/g) {
            push @found_ips, $&;
        }

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
    $self->_log(debug => "Returning: " . join(", ", @ips)) if @ips;

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

# -------------------- gatherer mode --------------------
sub run_gatherer {
    my ($self) = @_;
    my $delay = $self->{conf}->{propagation_delay} || 5;
    my @remote_servers = split(/\s*,\s*/, $self->{conf}->{remote_servers} || '');

    unless (@remote_servers) {
        $self->_log(error => "Gatherer mode requires remote_servers configured");
        die "No remote_servers configured for gatherer mode\n";
    }

    $self->_log(info => "Starting gatherer mode, polling " . scalar(@remote_servers) . " servers every ${delay}s");
    $self->_log(info => "Remote servers: " . join(", ", @remote_servers));

    $SIG{QUIT} = sub { $self->_log(info => "SIGQUIT"); exit 0; };
    $SIG{INT}  = sub { $self->_log(info => "SIGINT");  exit 0; };
    $SIG{TERM} = sub { $self->_log(info => "SIGTERM"); exit 0; };
    $SIG{HUP}  = sub { $self->_reload_config_signal(); };

    while (1) {
        eval {
            # Step 1: Gather blocks from all hunters
            $self->_log(debug => "Gathering blocks from remote servers...");
            my $collected = $self->_gather_from_remote_servers(\@remote_servers);

            # Step 2: Merge into local database
            $self->_log(debug => "Merging " . scalar(keys %$collected) . " unique IPs into database");
            $self->_merge_collected_blocks($collected);

            # Step 3: Propagate to all servers
            $self->_log(debug => "Propagating blocks to all servers...");
            $self->_propagate_blocks(\@remote_servers);

            $self->_log(info => "Gatherer cycle complete");
        };
        if ($@) {
            $self->_log(error => "Gatherer cycle failed: $@");
        }

        sleep $delay;
    }
}

sub _gather_from_remote_servers {
    my ($self, $servers) = @_;
    my %collected; # ip => { server => {...metadata...} }

    for my $server (@$servers) {
        $self->_log(debug => "Querying $server...");

        eval {
            my $timeout = $self->{conf}->{remote_server_timeout} || 10;
            my $query = q{sqlite3 /var/lib/bad_ips/bad_ips.sql "SELECT ip, originating_server, originating_service, detector_name, pattern_matched, matched_log_line, first_blocked_at, last_seen_at, expires_at, block_count FROM blocked_ips WHERE expires_at > strftime('%s', 'now')" 2>/dev/null};

            my $cmd = qq{timeout $timeout ssh -o ConnectTimeout=$timeout -o BatchMode=yes $server '$query'};
            my @lines = `$cmd 2>&1`;
            my $exit_code = $? >> 8;

            if ($exit_code != 0) {
                my $error = join('', @lines) || 'no error output';
                $error =~ s/\n/ /g;  # Collapse to single line
                $self->_log(warn => "Failed to query $server (exit code: $exit_code): $error");
                return;
            }

            # Parse SQLite output (pipe-delimited)
            for my $line (@lines) {
                chomp $line;
                my ($ip, $orig_server, $orig_service, $detector, $pattern, $log_line,
                    $first_blocked, $last_seen, $expires, $count) = split(/\|/, $line, 10);

                next unless $ip && $orig_server;

                $collected{$ip}{$orig_server} = {
                    originating_service => $orig_service,
                    detector_name => $detector,
                    pattern_matched => $pattern,
                    matched_log_line => $log_line,
                    first_blocked_at => $first_blocked,
                    last_seen_at => $last_seen,
                    expires_at => $expires,
                    block_count => $count
                };
            }

            $self->_log(debug => "Collected " . scalar(@lines) . " blocks from $server");
        };
        if ($@) {
            $self->_log(error => "Error querying $server: $@");
        }
    }

    return \%collected;
}

sub _merge_collected_blocks {
    my ($self, $collected) = @_;

    for my $ip (keys %$collected) {
        for my $server (keys %{$collected->{$ip}}) {
            my $data = $collected->{$ip}{$server};

            # UPSERT into blocked_ips
            my $sql = q{
                INSERT INTO blocked_ips (
                    ip, originating_server, originating_service, detector_name,
                    pattern_matched, matched_log_line,
                    first_blocked_at, last_seen_at, expires_at, block_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip, originating_server) DO UPDATE SET
                    last_seen_at = excluded.last_seen_at,
                    expires_at = excluded.expires_at,
                    block_count = excluded.block_count,
                    pattern_matched = excluded.pattern_matched,
                    matched_log_line = excluded.matched_log_line
            };

            eval {
                $self->{dbh}->do($sql, undef,
                    $ip, $server,
                    $data->{originating_service},
                    $data->{detector_name},
                    $data->{pattern_matched},
                    $data->{matched_log_line},
                    $data->{first_blocked_at},
                    $data->{last_seen_at},
                    $data->{expires_at},
                    $data->{block_count}
                );
            };
            if ($@) {
                $self->_log(error => "Failed to merge $ip from $server: $@");
            }
        }
    }
}

sub _propagate_blocks {
    my ($self, $servers) = @_;

    # Get all active blocks from database
    my $sql = q{
        SELECT DISTINCT ip, MAX(expires_at) as max_expires
        FROM blocked_ips
        WHERE expires_at > strftime('%s', 'now')
        GROUP BY ip
    };

    my $sth = $self->{dbh}->prepare($sql);
    $sth->execute();

    my @blocks;
    while (my ($ip, $expires) = $sth->fetchrow_array) {
        push @blocks, { ip => $ip, expires => $expires };
    }

    $self->_log(debug => "Propagating " . scalar(@blocks) . " blocks to " . scalar(@$servers) . " servers");

    for my $server (@$servers) {
        for my $block (@blocks) {
            my $ip = $block->{ip};
            my $expires = $block->{expires};
            my $ttl = $expires - time();
            next if $ttl <= 0;  # Skip expired

            # Check if already propagated
            my ($status) = $self->{dbh}->selectrow_array(
                "SELECT status FROM propagation_status WHERE ip = ? AND target_server = ?",
                undef, $ip, $server
            );

            if ($status && $status eq 'propagated') {
                # Already propagated, skip
                next;
            }

            # Try to propagate
            $self->_propagate_to_server($server, $ip, $ttl);
        }
    }
}

sub _propagate_to_server {
    my ($self, $server, $ip, $ttl) = @_;
    my $timeout = $self->{conf}->{remote_server_timeout} || 10;

    my $cmd = qq{timeout $timeout ssh -o ConnectTimeout=$timeout -o BatchMode=yes $server 'nft add element inet filter badipv4 { $ip timeout ${ttl}s }' 2>&1};

    my $output = `$cmd`;
    my $exit_code = $? >> 8;
    my $now = time();

    if ($exit_code == 0) {
        # Success
        $self->_log(debug => "Propagated $ip to $server (TTL: ${ttl}s)");

        my $sql = q{
            INSERT INTO propagation_status (ip, target_server, status, propagated_at, last_attempt, attempt_count)
            VALUES (?, ?, 'propagated', ?, ?, 1)
            ON CONFLICT(ip, target_server) DO UPDATE SET
                status = 'propagated',
                propagated_at = excluded.propagated_at,
                last_attempt = excluded.last_attempt,
                attempt_count = propagation_status.attempt_count + 1,
                error_message = NULL
        };

        eval { $self->{dbh}->do($sql, undef, $ip, $server, $now, $now) };
        $@ and $self->_log(error => "Failed to update propagation_status: $@");

    } else {
        # Failed
        chomp $output;
        $self->_log(warn => "Failed to propagate $ip to $server: $output");

        my $sql = q{
            INSERT INTO propagation_status (ip, target_server, status, last_attempt, attempt_count, error_message)
            VALUES (?, ?, 'failed', ?, 1, ?)
            ON CONFLICT(ip, target_server) DO UPDATE SET
                status = 'failed',
                last_attempt = excluded.last_attempt,
                attempt_count = propagation_status.attempt_count + 1,
                error_message = excluded.error_message
        };

        eval { $self->{dbh}->do($sql, undef, $ip, $server, $now, $output) };
        $@ and $self->_log(error => "Failed to update propagation_status: $@");
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
