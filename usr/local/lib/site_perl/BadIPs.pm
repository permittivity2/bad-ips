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
use Data::Dumper;

# Threading support
use threads;
use threads::shared;
use Thread::Queue;

$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 1;

our $VERSION = '2.0.25';

# Service -> how to read + patterns (moved to conf.d, kept empty here)
my %DETECTORS = ();

# Shared threading state
my $shutdown :shared = 0;
my $shutdown_start_time :shared = 0;

# Thread-safe queues (initialized in new())
# These are NOT shared variables themselves, but Thread::Queue handles thread-safety internally
my $ips_to_block_queue;
my $sync_to_central_db_queue;

# Random  platitudes for when the script ends such as "Have a nice day!"
my @platitudes = (
    "Have a nice day!",
    "Stay safe out there!",
    "Keep calm and block on!",
    "May your logs be ever clean!",
    "Happy blocking!",
    "Stay secure!",
    "Keep those IPs at bay!",
    "Wishing you a firewall-full day!",
    "Block wisely!",
    "May your connections be ever legitimate!",
    "Here’s to quieter logs tomorrow!",
    "May your packets travel true!",
    "Hope your firewall sleeps peacefully tonight!",
    "May your CPU loads stay forever low!",
    "Keep the bad guys guessing!",
    "Another day, another dropped packet!",
    "May your regexes match exactly what you intended!",
    "Stay frosty, sysadmin!",
    "May uptime be ever in your favor!",
    "Wishing you zero alerts today!",
    "Hope your coffee is strong and your logs are boring!",
    "May every suspicious IP expire gracefully!",
    "Here’s to clean metrics and silent pagers!",
    "May your network never loop!",
    "Stay sharp—malicious traffic never sleeps!",
    "May your patches apply without drama!",
    "Hope your backups restore flawlessly!",
    "May no one ever ask, 'Is the server down?'",
    "Wishing you a false-positive-free day!",
    "Here’s to swift blocks and smooth throughput!",
    "May your firewall rules stay readable!",
    "May your subnets stay peaceful and well-behaved!",
    "Onward to better security and fewer headaches!",
    "May your updates reboot quickly… or not at all!",
    "Stay vigilant and hydrated!",
    "May your incidents be minor and your logs verbose!",
    "Another glorious day in the land of packets!",
    "Hope your alerts come in twos, not hundreds!",
    "May your network traces make perfect sense… for once!",
    "Wishing you less noise and more signal!",
    "May the bandwidth gods favor your side today!",
    "Here’s to fewer threats and more snacks!",
    "Hope your firewall rules never get out of order!",
    "May your syslog be pleasantly boring!",
    "Keep the packets flowing and the nonsense out!",
    "May your tables never overflow!",
    "Be well, and block boldly!",
    "May your IPv6 configs behave themselves!",
    "Here’s to logs that tell the truth and nothing but!",
    "May every rogue IP meet a swift DROP!",
    "Wishing you stable links and cheerful pings!",
    "Hope no one DDoSes your serenity today!",
    "May your queues stay empty and your spirits high!",
    "Stay curious, stay cautious!",
    "Wishing you clean code and clean connections!",
    "May your firewall never betray you!",
    "Hope your network behaves better than its users!",
);


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
    # $self->_init_db();                  # Local SQLite
    $self->_init_central_db();          # Central PostgreSQL
    $self->_initial_load_blocked_ips();
    $self->_refresh_static_nftables_sets();  # Populate static sets at startup
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
    $accum{sleep_time}                //= 2;
    $accum{heartbeat}                 //= 60;
    $accum{extra_time}                //= 120;
    $accum{initial_journal_lookback}  //= 300;  # 5 minutes (reduced from 24 hours to minimize memory usage)
    $accum{journal_units}             //= 'ssh';
    $accum{bad_conn_patterns}         //= 'Failed password for invalid user,Failed password for root,Failed password for,Failed password for .* from,Failed password for .* from .* port';
    # never_block_cidrs should ALWAYS be defined in badips.conf - no hardcoded default
    # This prevents accidentally blocking trusted networks if config is missing
    $accum{never_block_cidrs}         //= '';
    # always_block_cidrs should be defined in badips.conf for known bad actors
    $accum{always_block_cidrs}        //= '';
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
    $accum{journal_units}      = _csv_to_array($accum{journal_units});
    $accum{bad_conn_patterns}  = _csv_to_array($accum{bad_conn_patterns});
    $accum{never_block_cidrs}  = _csv_to_array($accum{never_block_cidrs});
    $accum{always_block_cidrs} = _csv_to_array($accum{always_block_cidrs});
    $accum{file_sources}       = _csv_to_array($accum{file_sources});

    $self->{conf} = \%accum;

    # Phase 10: Add threading configuration defaults
    $self->{conf}->{ips_to_block_queue_max}                 //= 5000;
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
    $self->{conf}->{db_host}                                //= 'localhost';
    $self->{conf}->{db_port}                                //= 5432;
    $self->{conf}->{db_name}                                //= 'bad_ips';
    $self->{conf}->{db_user}                                //= 'bad_ips_hunter';
    $self->{conf}->{db_password}                            //= '';
    $self->{conf}->{db_ssl_mode}                            //= 'disable';

    my $confs;
    # Take all the keys and values of accum and self->con and put them in confs
    my @accums_keys = qw/
        conf_main conf_dir
        blocking_time sleep_time heartbeat extra_time initial_journal_lookback
        journal_units bad_conn_patterns never_block_cidrs always_block_cidrs
        db_dir db_file log_level nft_table nft_family_table nft_set
        file_sources max_file_tail_lines auto_mode
        ips_to_block_queue_max sync_to_central_db_queue_max
        sync_to_central_db_queue_critical_time central_db_batch_size
        central_db_batch_timeout pull_min_interval pull_step_interval
        pull_initial_interval pull_max_interval failover_log failover_enabled
        graceful_shutdown_timeout
        db_type db_host db_port db_name db_user db_password db_ssl_mode/;
    for my $k (@accums_keys) {
        $confs->{$k} = exists $self->{conf}->{$k} ? $self->{conf}->{$k} : '';
        $confs->{$k} = exists $accum{$k} ? $accum{$k} : '';
    }

    return $confs;
}

# Initialize thread-safe queues
sub _init_queues {
    my ($self) = @_;

    $ips_to_block_queue = Thread::Queue->new();
    $sync_to_central_db_queue = Thread::Queue->new();

    $log->debug("Initialized thread-safe queues");
}

# Initialize central PostgreSQL database connection
sub _init_central_db {
    my ($self) = @_;

    return if $self->{dry_run};

    my $conf = $self->{conf};

    # Check if database is configured
    unless ($conf->{db_host} && $conf->{db_password}) {
        $log->warn("PostgreSQL not configured (missing db_host or db_password)");
        $log->warn("Central DB sync will be disabled");
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
        $log->info("Connected to PostgreSQL: $conf->{db_host}:$conf->{db_port}/$conf->{db_name}");
    };

    if ($@) {
        $log->info("Failed to connect to PostgreSQL: $@");
        $log->warn("Central DB sync will be disabled");
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
        $log->info("Thread DB connection failed: $@");
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
        $log->warn("Cannot open conf.d dir $dir");
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
        $log->info("AUTO: no detectors defined; keeping static config");
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
            if ($@) { $log->warn("Bad pattern in $key: $p ($@)"); next; }
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
                    $log->info("[dry-run] would probe remote services: $cmd");
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
                        $log->warn("ssh probe failed for $key; skipping remote journald");
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
    $log->info("AUTO(detectors): units=$units_msg files=$files_msg patterns=" . scalar(@final_pats));
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
    my $all_confs = $self->_load_config();
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

    my $sql = q{
        INSERT INTO jailed_ips (
            ip, originating_server, originating_service, detector_name,
            pattern_matched, matched_log_line,
            first_blocked_at, last_seen_at, expires_at, block_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(ip, originating_server) DO UPDATE SET
            last_seen_at = excluded.last_seen_at,
            expires_at = excluded.expires_at,
            block_count = jailed_ips.block_count + 1,
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
        $log->info("Failed to insert into jailed_ips for $ip: $@");
    }
}

# Thread-safe versions that accept a database handle parameter
sub _db_upsert_jailed_ip_with_handle {
    my ($self, $dbh, $ip, $expires_epoch) = @_;
    my $now = int(time());

    my $sql = q{
        INSERT INTO jailed_ips (ip, first_jailed_at, last_jailed_at, expires_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            last_jailed_at = excluded.last_jailed_at,
            expires_at = excluded.expires_at
    };

    my $sth = $dbh->prepare($sql);
    $sth->execute($ip, $now, $now, int($expires_epoch));
}

sub _db_upsert_blocked_ip_with_handle {
    my ($self, $dbh, $ip, $expires_epoch, $metadata) = @_;
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

    my $sql = q{
        INSERT INTO jailed_ips (
            ip, originating_server, originating_service, detector_name,
            pattern_matched, matched_log_line,
            first_blocked_at, last_seen_at, expires_at, block_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(ip, originating_server) DO UPDATE SET
            last_seen_at = excluded.last_seen_at,
            expires_at = excluded.expires_at,
            block_count = jailed_ips.block_count + 1,
            pattern_matched = excluded.pattern_matched,
            matched_log_line = excluded.matched_log_line
    };

    eval {
        $dbh->do($sql, undef,
            $ip, $hostname, $service, $detector,
            $pattern, $log_line,
            $now, $now, int($expires_epoch)
        );
    };
    if ($@) {
        $log->info("Failed to insert into jailed_ips for $ip: $@");
    }
}

# -------------------- main loop --------------------
sub run {
    my ($self) = @_;

    $log->info("Starting Bad IPs monitoring system (multi-threaded with distributed threat intelligence)");
    return $self->run_hunter();
}

# ==================== PHASE 10: THREAD FUNCTIONS ====================

# Thread: nft_blocker_thread
# CRITICAL: This thread must NEVER block on I/O
# Purpose: Pop from ips_to_block_queue, add to nftables
sub nft_blocker_thread {
    my ($self) = @_;
    $log->info("nft_blocker_thread started");

    my $set = $self->{conf}->{nft_set};
    my $tab = $self->{conf}->{nft_family_table};
    my $fam = $self->{conf}->{nft_table};
    my $ttl = $self->{conf}->{blocking_time};

    while ( my $item = $ips_to_block_queue->dequeue() ) {
        if ( $shutdown and ! $item ) {  # if shutdown and queue is drained
            $log->info("nft_blocker_thread: shutdown signal received and queue drained, exiting");
            last;
        }

        $log->info("nft_blocker_thread: processing IP $item->{ip}");

        my $ip = $item->{ip};
        my $source = $item->{source} || 'unknown';
        my $detector = $item->{detector} || 'unknown';
        my $log_line = $item->{line};

        # Skip if already blocked
        if (exists $self->{blocked}{$ip}) {
            $log->debug("Skipping already-blocked IP: $ip");
            next;
        }

        # Check never_block_cidrs
        if ($self->_is_never_block_ip($ip)) {
            $log->debug("Skipping never-block IP: $ip");
            next;
        }

        # Execute nft command (FAST - no I/O wait!)
        my $cmd = "nft add element $fam $tab $set { $ip timeout ${ttl}s }";

        if ($self->{dry_run}) {
            $log->info("[dry-run] would jail $ip for ${ttl}s");
            my $exp = time() + $ttl;
            $self->{blocked}{$ip} = $exp;

            # Even in dry-run, queue for central DB (skip local SQLite)
            $sync_to_central_db_queue->enqueue({
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

            $log->info("Jailed $ip for ${ttl}s (source: $source, detector: $detector)");

            # Enqueue directly to sync_to_central_db_queue
            my $q_entry = {
                ip => $ip,
                expires_at => $exp,
                source => $source,
                detector => $detector,
                log_line => $log_line,
            };
            $sync_to_central_db_queue->enqueue($q_entry);
            $log->debug("Enqueued $ip to sync_to_central_db_queue");
            $log->debug("queue contents:\n" . Dumper($q_entry));
        } else {
            $log->info("nft add failed for $ip: $!");
        }
    }

    $log->info("nft_blocker_thread shutting down");
}

# Helper: Check if IP is in never_block_cidrs
sub _is_never_block_ip {
    my ($self, $ip) = @_;
    my $cidrs = $self->{conf}->{never_block_cidrs} || [];
    return 0 unless @$cidrs;
    return cidrlookup($ip, @$cidrs);
}

# Thread: central_db_sync_thread
# Purpose: Pop from sync_to_central_db_queue (batched), write to PostgreSQL
sub central_db_sync_thread {
    my ($self) = @_;
    $log->info("central_db_sync_thread started");

    # Create thread-local database connection
    my $thread_dbh = $self->_create_thread_db_connection();
    unless ($thread_dbh) {
        $log->warn("central_db_sync_thread: no database connection, exiting");
        return;
    }
    $log->info("central_db_sync_thread: established thread-local DB connection");

    # The default values below should have been set long before reaching here.  These are just safeguards.
    my $batch_size = $self->{conf}->{central_db_batch_size} || 50;
    my $queue_max  = $self->{conf}->{sync_to_central_db_queue_max} || 500;

    $log->info("Starting dequeuer of central_db_sync_thread: " . 
        "batch_size=$batch_size queue_max=$queue_max");
    my $continue = 1;
    while ($continue) {
        $log->debug("central_db_sync_thread: queue size before dequeue: " . $sync_to_central_db_queue->pending());
        my $item = $sync_to_central_db_queue->dequeue();
        my @batch = ();
        push @batch, $item if $item;
        while ( @batch < $batch_size ) {
            my $next_item = $sync_to_central_db_queue->dequeue_nb() || undef;
            if ( !defined $next_item ) {
                last;  # Queue is empty
            }
            push @batch, $next_item;
        }
        $log->debug("central_db_sync_thread: dequeued " . scalar(@batch) . " item" . (scalar(@batch) == 1 ? '' : 's') . " from queue");
        $log->debug("central_db_sync_thread: batch contents:\n" . Dumper(@batch)) if @batch;
        if ( @batch ) {
            eval {
                $self->_db_upsert_blocked_ip_with_handle_multiple_items($thread_dbh, \@batch);
            };
            if ($@) {
                $log->info("Central DB batch INSERT failed: $@, requeueing " . scalar(@batch) . " item" . (scalar(@batch) == 1 ? '' : 's'));
                $sync_to_central_db_queue->enqueue($_) for @batch;
                sleep 10;  # Back off
            } else {
                my @ips = map { $_->{ip} } @batch;
                $log->info("Synced " . scalar(@batch) . " IP" . (scalar(@batch) == 1 ? '' : 's') . " to central DB: " . join(", ", @ips));  
                $log->debug("Synced IPs to central DB:\n" . Dumper(\@batch));
            }
        }

        if ( !@batch and $shutdown ) {
            $log->info("central_db_sync_thread: shutdown signal received and queue drained, exiting");
            $sync_to_central_db_queue->end(); # Just a safety measure
            $continue = 0;
        } 
    }

    # Close thread-local connection
    $thread_dbh->disconnect() if $thread_dbh;
    $log->info("central_db_sync_thread is shutting down.  The sync_to_central_db_queue should be empty now.");
}

sub _db_upsert_blocked_ip_with_handle_multiple_items {
    my ($self, $dbh, $batch) = @_;
    my @batch = ref $batch ? @$batch : ();
    return unless @batch;
    my $now = int(time());
    my $hostname = $self->{conf}->{hostname} || hostname();
    chomp $hostname;

    my $sql = "INSERT INTO jailed_ips (
        ip, originating_server, originating_service, detector_name,
        pattern_matched, matched_log_line,
        first_blocked_at, last_seen_at, expires_at, block_count
    ) VALUES ";
    my @placeholders;
    my @values;
    for my $item (@batch) {
        push @placeholders, "(?, ?, ?, ?, ?, ?, ?, ?, ?, 1)";
        push @values,
            $item->{ip},
            $hostname,
            $item->{source},
            $item->{detector},
            'unknown',  # pattern_matched
            substr($item->{log_line} || '', 0, 500),  # matched_log_line (truncated)
            int(time()),  # first_blocked_at
            int(time()),  # last_seen_at
            int($item->{expires_at});
    }
    $sql .= join(", ", @placeholders);
    $sql .= " ON CONFLICT(ip, originating_server) DO UPDATE SET
        last_seen_at = excluded.last_seen_at,
        expires_at = excluded.expires_at,
        block_count = jailed_ips.block_count + 1,
        pattern_matched = excluded.pattern_matched,
        matched_log_line = excluded.matched_log_line";
    $log->debug("central_db_sync_thread: executing batch INSERT SQL:\n$sql\nwith values:\n" . Dumper(\@values));
    my $sth = $dbh->prepare($sql);
    $sth->execute(@values);
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
        $log->info("Failed to write failover log: $@");
        return 0;
    };

    return 1;
}

# Thread: pull_global_blocks_thread
# Purpose: Query central DB for new blocks, push to ips_to_block_queue (adaptive interval)
sub pull_global_blocks_thread {
    my ($self) = @_;
    $log->info("pull_global_blocks_thread started");

    # Create thread-local database connection
    my $thread_dbh = $self->_create_thread_db_connection();
    unless ($thread_dbh) {
        $log->warn("pull_global_blocks_thread: no database connection, exiting");
        return;
    }
    $log->info("pull_global_blocks_thread: established thread-local DB connection");

    my $min_interval    = $self->{conf}->{pull_min_interval};
    my $pull_interval   = $self->{conf}->{pull_initial_interval};
    my $max_interval    = $self->{conf}->{pull_max_interval};
    my $step            = $self->{conf}->{pull_step_interval};
    my $last_check_time = time();

    while (!$shutdown) {
        sleep $pull_interval;
        last if $shutdown;

        my $new_blocks_found = 0;

        # Query central DB for new blocks
        eval {
            my $hostname = hostname();
            my $sth = $thread_dbh->prepare(
                "SELECT ip, originating_server, originating_service, detector_name
                 FROM jailed_ips
                 WHERE originating_server != ?
                 AND last_seen_at > ?"
            );
            $sth->execute($hostname, int($last_check_time));

            while (my $row = $sth->fetchrow_hashref) {
                $new_blocks_found++;

                # Enqueue for blocking
                $ips_to_block_queue->enqueue({
                    ip => $row->{ip},
                    source => "central_db:$row->{originating_server}",
                    detector => $row->{detector_name} || 'global_sync',
                    line => undef,
                });
            }

            $last_check_time = time();
        };

        if ($@) {
            $log->info("Failed to pull global blocks: $@");
            sleep 10;  # Back off on error
            next;
        }

        if ($new_blocks_found > 0) {
            $log->info("Pulled $new_blocks_found new blocks from central DB");
        }
    }

    # Close thread-local connection
    $thread_dbh->disconnect() if $thread_dbh;
    $log->info("pull_global_blocks_thread shutting down");
}

# Thread: log_watcher_thread (generic)
# Purpose: Watch logs (file or journalctl), find bad IPs, push to ips_to_block_queue
# Note: Phase 10 uses existing _read_all_sources() in main thread for now
# TODO Phase 10.1: Refactor into per-detector threads with proper file position tracking
sub log_watcher_thread {
    my ($self, $detector_name, $detector_config) = @_;
    $log->info("log_watcher_thread started for detector: $detector_name");

    # This is a placeholder for future per-detector threading
    # For Phase 10, we'll continue using the existing _read_all_sources() approach
    # in the main run_hunter loop, but enqueue to ips_to_block_queue

    $log->warn("Per-detector log watcher threads not yet implemented in Phase 10");
    $log->info("log_watcher_thread shutting down");
}

# Graceful shutdown handler
sub _shutdown_gracefully {
    my ($self, $signal) = @_;
    $log->info("Received $signal, initiating graceful shutdown");

    {
        lock($shutdown);
        $shutdown = 1;
        $shutdown_start_time = time();
    }

    my $timeout = $self->{conf}->{graceful_shutdown_timeout};
    $log->info("Allowing up to ${timeout}s for threads to drain queues");

    # Main thread will handle joining worker threads
}

sub run_hunter {
    my ($self) = @_;
    $log->info("Starting main thread to find and block bad IPs");
    my $start_time = time();

    # Setup signal handlers for graceful shutdown
    $SIG{QUIT} = sub { $self->_shutdown_gracefully("SIGQUIT"); };
    $SIG{INT}  = sub { $self->_shutdown_gracefully("SIGINT"); };
    $SIG{TERM} = sub { $self->_shutdown_gracefully("SIGTERM"); };
    $SIG{HUP}  = sub { $self->_reload_config_signal(); };

    # Start worker threads
    $log->info("Starting worker threads...");
    my $confs = $self->_load_config();
    for my $method_name ( qw/nft_blocker_thread central_db_sync_thread pull_global_blocks_thread/ ) {
        $log->info("Starting $method_name");
        # push @{$self->{threads}}, threads->create(sub { $self->$method_name() });
        my $thr = threads->create(\&{$method_name}, $self);
        push @{$self->{threads}}, $thr;
    }
    $log->info("All worker threads started");

    # Main loop: Read logs and enqueue IPs for blocking
    my $hb_at = time() + $self->{conf}->{heartbeat};
    my %new_since_hb;

    # Initial log read
    my $read_journal_epoch = int(time());
    my $entries = $self->_read_all_sources(
        max_file_lines   => $self->{conf}->{max_file_tail_lines},
        read_journal_since  => int(time()) - $self->{conf}->{initial_journal_lookback},
    );

    while (!$shutdown) {
        $self->{run_count}++;
        $log->debug("Run #$self->{run_count}: processing log entries");

        # Process log entries
        my $bad = {};                                                                                                                                                                               
        $bad = $self->_bad_entries($entries) if ( keys %{$entries || {}} );                                                                                                                         
        my $ip_data = [];                                                                                                                                                                           
        $ip_data = $self->_remote_addresses($bad) if ( keys %{$bad} );        

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

        $log->debug("Run #$self->{run_count}: enqueued " . scalar(@$ip_data) . " IPs for blocking");
        $log->debug("Run #$self->{run_count} complete, sleeping for " . $self->{conf}->{sleep_time} . " seconds");
        sleep $self->{conf}->{sleep_time};
        $self->_remove_expired_ips();

        # Heartbeat
        if ( time() > $hb_at ) {
            $self->heartbeat_info( heartbeat_interval => $self->{conf}->{heartbeat}, new_since_hb => \%new_since_hb );
            $hb_at = time() + $self->{conf}->{heartbeat};
            %new_since_hb = ();
        }

        # Re-read logs
        my $current_read_journal_epoch = int(time());
        $entries = $self->_read_all_sources(
            max_file_lines      => $self->{conf}->{max_file_tail_lines},
            read_journal_since  => $read_journal_epoch,
        );
        $read_journal_epoch = $current_read_journal_epoch;
    }

    # Shutdown: wait for threads to complete
    $log->info("Main loop exiting, waiting for threads to drain queues...");
    $self->_drain_queues();

    for my $thr (@{$self->{threads}}) {
        $thr->join();
    }

    my $goodbye_msg = "All threads joined, exiting gracefully.  Thank you.  ";
    # Add random array element from @platitudes
    my $random_index = int(rand(scalar(@platitudes)));
    $goodbye_msg .= $platitudes[$random_index];
    $log->info($goodbye_msg);

    my $end_time = time();
    my $duration = $end_time - $start_time;
    # make a pretty print human readable duration
    my $hours = int($duration / 3600);
    my $minutes = int(($duration % 3600) / 60);
    my $seconds = $duration % 60;
    $log->info("Total runtime: ${hours}h ${minutes}m ${seconds}s");

    $log->info("The End.");
    return 1;
}

sub _drain_queues {
    my ($self) = @_;
    my $graceful_shutdown_timeout = $self->{conf}->{graceful_shutdown_timeout} || 20;
    my $max_wait_time;

    # 1. Add end to ips_to_block_queue then wait for it to be drained
    $ips_to_block_queue->end();
    my $pending = $ips_to_block_queue->pending() || 0;
    $log->info("Waiting for ips_to_block_queue to drain.  Will wait up to " . $graceful_shutdown_timeout . " seconds.  Pending: " . $pending);
    $max_wait_time = time() + $graceful_shutdown_timeout;
    while ( ( $pending > 0 ) && ( time() < $max_wait_time ) ) {
        $pending = $ips_to_block_queue->pending() || 0;
        sleep 2;
    }
    if ( $pending > 0 ) {
        $log->warn("Timeout reached while draining ips_to_block_queue, pending: " . $pending);
    }

    # 2. Add end to sync_to_central_db_queue then wait for it to be drained
    $sync_to_central_db_queue->end();
    $pending = $sync_to_central_db_queue->pending() || 0;
    $log->info("Waiting for sync_to_central_db_queue to drain.  Will wait up to " . $graceful_shutdown_timeout . " seconds.  Pending: " . $pending);
    $max_wait_time = time() + 20;  # max 20 seconds to drain
    while ( ( $pending > 0 ) && ( time() < $max_wait_time ) ) {
        $pending = $sync_to_central_db_queue->pending() || 0;
        sleep 2;
    }
    if ( $pending > 0 ) {
        $log->warn("Timeout reached while draining sync_to_central_db_queue, pending: " . $pending);
    }

    # Go through each queue and do a dequeue_nb to clear any remaining items
    while ( my $item = $ips_to_block_queue->dequeue_nb() ) {
        $log->debug("Draining ips_to_block_queue item: " . Dumper($item));
    }
    while ( my $item = $sync_to_central_db_queue->dequeue_nb() ) {
        $log->debug("Draining sync_to_central_db_queue item: " . Dumper($item));
    }
}

sub heartbeat_info {
    my ($self, %args) = @_;
    my $interval = $args{heartbeat_interval} // 300;
    my $new_since_hb = $args{new_since_hb} // {};
    my %new_since_hb = %$new_since_hb;

    $self->_reload_blocked_ips();

    my @sorted = sort { $self->{blocked}{$a} <=> $self->{blocked}{$b} } keys %{$self->{blocked}};
    my @new_ips = sort { $a cmp $b } keys %new_since_hb;

    $log->info("Heartbeat: Total blocked IPs: " . scalar(@sorted));
    $log->info("Run count: $self->{run_count}");
    $log->info("Queue depths: ips_to_block=" . $ips_to_block_queue->pending() .
                        ", sync=" . $sync_to_central_db_queue->pending());

    if (@new_ips) {
        $log->info("Newly blocked since last heartbeat (" . scalar(@new_ips) . "): " . join(", ", @new_ips));
    } else {
        $log->info("No new IPs since last heartbeat");
    }
}

# -------------------- Read All Sources --------------------
sub _read_all_sources {
    my ($self, %args) = @_;
    my $max                 = $args{max_file_lines}   // 2000;
    my $sleep_time          = $self->{conf}->{sleep_time} // 60;
    my $read_journal_since  = $args{read_journal_since} // time() - $sleep_time;

    # 1) journald units
    # my $entries = $self->_read_journals($jl);
    my $entries = $self->_read_journals($read_journal_since);

    # 2) file sources
    my $files = $self->{conf}->{file_sources} || [];
    if (@$files) {
        my $file_entries = $self->_read_files_recent($files, $max);
        for my $unit (keys %$file_entries) {
            $entries->{$unit} = $file_entries->{$unit};
        }
        $log->debug("Merged file sources: " . join(", ", @$files));
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
            $log->warn("Could not open $path for backward read");
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
    my ($self, $read_journal_since) = @_;
    my $seconds_ago = time() - $read_journal_since;
    my $entries = {};
    my $units = $self->{conf}->{journal_units} || [];
    for my $unit (@$units) {
        $log->debug("Reading journal for unit $unit since epoch $read_journal_since ($seconds_ago seconds ago)");
        my $u = $self->_read_journal_unit($unit, $read_journal_since);
        $log->debug("Found " . scalar(keys %$u) . " entries with IPv4s in unit $unit");
        $log->debug("Entries for unit $unit: " . Dumper($u));
        $entries->{$unit} = $u;
    }
    return $entries;
}

sub _get_journal_byte_count {
    my ($self, %args) = @_;
    my $unit = $args{unit} // '';
    my $since_epoch = $args{since_epoch} // time();
    my $until_epoch = $args{until_epoch} // time();

    my $cmd = qq(journalctl --unit=$unit --since=\@$since_epoch --until=\@$until_epoch --no-pager -o json | wc -c);
    $log->debug("Executing command to get byte count: $cmd");
    my $output = `$cmd 2>/dev/null`;
    chomp $output;
    if ($? != 0) {
        $log->warn("Failed to get journal byte count for unit $unit");
        return 0;
    }
    return int($output);
}

sub _get_journal_lines {
    my ($self, %args) = @_;
    my $unit = $args{unit} // '';
    my $since_epoch = $args{since_epoch} // time();
    my $until_epoch = $args{until_epoch} // time();
    
    my @lines = ();

    my $cmd = "journalctl --unit=$unit --since=\@$since_epoch --until=\@$until_epoch --no-pager -o json";

    open(my $fh, "-|", $cmd) or do {
        $log->warn("Failed to open journalctl command for unit $unit: $!");
        return \@lines;
    };

    while (my $line = <$fh>) {
        chomp $line;

        next unless $line =~ /\S/;  # skip empty

        next unless ( $self->has_ipv4($line) or $self->has_ipv6($line) );  # skip if no IPs

        # Now decode the JSON and process it
        my $entry = eval { decode_json($line) };
        if ($@) {
            warn "JSON decode error: $@ -- line was: $line";
            $log->warn("Failed to parse journalctl JSON line: $@");
            next;
        }
        my $line_hash = {};
        $line_hash->{MESSAGE} = $entry->{MESSAGE} // '';

        push @lines, $line_hash if ( $self->has_ipv4($line_hash->{MESSAGE}) or $self->has_ipv6($line_hash->{MESSAGE}) );
    }

    close($fh);

    return \@lines;

}

sub _read_journal_unit {
    my ($self, $unit, $read_journal_since) = @_;
    $read_journal_since = int($read_journal_since); # Make sure it's an integer
    my $seconds_ago = time() - $read_journal_since;

    my $entries = {};    
    my $byte_count;
    if ( $log->is_debug() ) {
        $byte_count = $self->_get_journal_byte_count( unit => $unit, since_epoch => $read_journal_since );
        # convert bytes to human readable
        my $human_readable = $byte_count < 1024 ? "$byte_count B" :
                            $byte_count < 1048576 ? sprintf("%.2f KB", $byte_count / 1024) :
                            $byte_count < 1073741824 ? sprintf("%.2f MB", $byte_count / 1048576) :
                            sprintf("%.2f GB", $byte_count / 1073741824);
        $log->debug("Journal byte count for unit $unit since epoch $read_journal_since: $human_readable");
    }

    my $lines = $self->_get_journal_lines( unit => $unit, since_epoch => $read_journal_since, until_epoch => time() );
    my @lines_arr = ref($lines) eq 'ARRAY' ? @$lines : ();
    $log->debug("Total journal entries retrieved for unit $unit: " . scalar(@lines_arr));
    my %lines_hash = ();
    my $counter = 1;
    for my $line (@lines_arr) {
        my $msg = $line->{MESSAGE} || '';
        $lines_hash{$msg} = $counter++;
    }
    $log->debug("Filtered journal entries with IPs for unit $unit: " . scalar(keys %lines_hash));

    # Previous code looked for a threadid, but journalctl does not provide that, we will fake it with a counter set above
    for my $msg (keys %lines_hash) {
        my $threadid = $lines_hash{$msg} || 'unknown';
        $threadid = "$unit:$threadid";
        $entries->{$threadid} = defined $entries->{$threadid} ? "$entries->{$threadid}|$msg" : $msg;
    }

    $log->debug("Returning " . scalar(keys %$entries) . " entries with IPv4s or IPv6s from journalctl for unit $unit");
    return $entries;
}

# Return true if string has an IPv4 address anywhere in it
sub has_ipv4 {
    my ($self, $string) = @_;

    return ($string =~ /$RE{net}{IPv4}/) ? 1 : 0;
}

# Return true if string has an IPv6 address anywhere in it
sub has_ipv6 {
    my ($self, $string) = @_;
    return ($string =~ /$RE{net}{IPv6}/) ? 1 : 0;
}

=head2 _bad_entries

    Description: Filters log entries against bad connection patterns.
    Input: Hashref of log entries by unit.
    Output: Hashref of bad entries with metadata.
=cut
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
    $log->debug("Checking $total_entries log entries against " . scalar(@$patterns) . " patterns");

    for my $unit (keys %$entries) {
        my $u = $entries->{$unit};
        $log->debug("Processing unit: $unit (" . scalar(keys %$u) . " entries)");
        ENTRY: for my $pid (keys %$u) {
            my $msg = $u->{$pid};
            my $pattern_num = 0;
            for my $re (@$patterns) {
                $pattern_num++;
                if ($msg =~ $re) {
                    # Store message with metadata
                    my $pattern = $self->{conf}->{bad_conn_patterns}->[$pattern_num-1] || 'unknown';
                    $bad{$pid} = {
                        msg => $msg,
                        unit => $unit,
                        pattern_num => $pattern_num,
                        pattern => $pattern,
                        detector => $self->_detector_name_from_unit($unit),
                        service => $self->_service_name_from_unit($unit)
                    };
                    $log->debug("Unit $unit matched pattern#$pattern_num: $pattern");
                    $log->debug("Matched log line: " . substr($msg, 0, 100) . (length($msg) > 100 ? "..." : ""));
                    last ENTRY;
                }
            }
        }
    }
    $log->debug("Found " . scalar(keys %bad) . " bad entries");
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

    $log->debug("Extracting IPs from " . scalar(keys %$entries) . " bad entries");
    $log->debug("Bad entries detail:\n" . Dumper($entries));

    for my $k (keys %$entries) {
        my $entry = $entries->{$k};
        my $msg = ref($entry) eq 'HASH' ? $entry->{msg} : $entry;

        # Extract all IPs from this message
        my @found_ips;
        while ($msg =~ /$RE{net}{IPv4}/g) {
            push @found_ips, $&;
        }

        $log->debug("Extracted " . scalar(@found_ips) . " IPs from log entry") if @found_ips;

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
                    $log->debug("Found IP $ip from detector '$entry->{detector}'");
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
        $log->debug("Extracted " . scalar(@ips) . " unique IPs: " . join(", ", @ips));
    } else {
        $log->debug("No IPs extracted from bad entries");
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
                $log->info("IP $ip is in $cidr; skipping");
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

    $log->debug("Already blocked: " . join(',', @already)) if @already;
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
            $log->info("[dry-run] would jail $ip for ${ttl}s with: $cmd");
            my $exp = time() + $ttl;
            $self->{blocked}{$ip} = $exp;
            next; # do not touch DB in dry-run
        }

        if (system($cmd) == 0) {
            my $exp = time() + $ttl;
            $self->{blocked}{$ip} = $exp;

            # Insert into both old and new tables (dual-write)
            eval { $self->_db_upsert_jailed_ip($ip, $exp) };
            $@ and $log->info("SQLite upsert (jailed_ips) failed for $ip: $@");

            eval { $self->_db_upsert_blocked_ip($ip, $exp, $metadata) };
            $@ and $log->info("SQLite upsert (blocked_ips) failed for $ip: $@");

            my $svc = $metadata->{service} || 'unknown';
            my $det = $metadata->{detector} || 'unknown';
            $self->_log(info  => "Jailed $ip for ${ttl}s (service: $svc, detector: $det)");
        } else {
            my $err = $!;
            $log->info("nft add failed for $ip: $err");
        }
    }
}

sub _remove_expired_ips {
    my ($self) = @_;
    my $now = time();
    for my $ip (keys %{$self->{blocked}}) {
        if ($now > $self->{blocked}{$ip}) {
            $log->info("Parolling $ip from in-memory cache");
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
            # eval { $self->_db_upsert_jailed_ip($ip, $expires) };
            # $@ and $log->info("SQLite sync failed for $ip: $@");
        }
    }
}

sub _nft_as_json {
    my ($self) = @_;
    my $out = `nft -j list ruleset`;
    return decode_json($out);
}

sub _refresh_static_nftables_sets {
    my ($self) = @_;

    my $table = $self->{conf}->{nft_table};
    my $family_table = $self->{conf}->{nft_family_table};

    # Refresh never_block set
    $log->info("Refreshing never_block nftables set");
    my $never_block_cidrs = $self->{conf}->{never_block_cidrs} || [];

    # Flush the set and repopulate
    system("nft flush set $table $family_table never_block 2>/dev/null");

    for my $cidr (@$never_block_cidrs) {
        next unless $cidr;
        $cidr =~ s/^\s+|\s+$//g;  # trim whitespace
        next unless $cidr;

        # Handle both single IPs and CIDRs
        my $result = system("nft add element $table $family_table never_block { $cidr } 2>/dev/null");
        if ($result == 0) {
            $log->debug("Added $cidr to never_block set");
        } else {
            $log->info("Failed to add $cidr to never_block set");
        }
    }

    # Refresh always_block set
    $log->info("Refreshing always_block nftables set");
    my $always_block_cidrs = $self->{conf}->{always_block_cidrs} || [];

    # Flush the set and repopulate
    system("nft flush set $table $family_table always_block 2>/dev/null");

    for my $cidr (@$always_block_cidrs) {
        next unless $cidr;
        $cidr =~ s/^\s+|\s+$//g;  # trim whitespace
        next unless $cidr;

        # Handle both single IPs and CIDRs
        my $result = system("nft add element $table $family_table always_block { $cidr } 2>/dev/null");
        if ($result == 0) {
            $log->info("Added $cidr to always_block set");
        } else {
            $log->info("Failed to add $cidr to always_block set");
        }
    }

    my $never_count = scalar(@$never_block_cidrs);
    my $always_count = scalar(@$always_block_cidrs);
    $log->info("Static sets refreshed: $never_count never_block, $always_count always_block");
}

# -------------------- signal handlers --------------------
sub _reload_config_signal {
    my ($self) = @_;
    my $confs;
    eval {
        $log->info("SIGHUP received: reloading configuration");
        $confs = $self->_load_config();
        $self->{detectors} = $self->_load_detectors_from_confdir();
        $self->_auto_discover_sources();
        $self->_refresh_static_nftables_sets();
        $log->info("New config:\n" . $self->_report_config());
    };
    if ($@) {
        $log->info("Failed to reload config on SIGHUP: $@");
    }

    return $confs;
}

# -------------------- tiny logger shim --------------------
sub _log {
    my ($self, $lvl, $msg) = @_;
    $lvl ||= 'info';
    my $meth = $log->can($lvl) ? $lvl : 'info';
    $log->$meth($msg);
}

1;


