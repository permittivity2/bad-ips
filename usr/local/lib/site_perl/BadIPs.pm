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

# -------------------- main loop --------------------
sub run {
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
        my $ips = $self->_remote_addresses($bad);
        $ips    = $self->_remove_never_block_ips($ips);
        $ips    = $self->_remove_already_blocked_ips($ips);

        map { $new_since_hb{$_} = 1 } @$ips if @$ips;

        $self->_add_ips_to_nft($ips);
        $self->_log(debug => "Run #$self->{run_count}: blocked " . scalar(@$ips) . " new IPs");

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
            for my $re (@$patterns) {
                if ($msg =~ $re) {
                    $bad{$pid} = $msg;
                    $self->_log(debug => "Unit $unit matched");
                    last ENTRY;
                }
            }
        }
    }
    return \%bad;
}

sub _remote_addresses {
    my ($self, $entries) = @_;
    my @ips;
    for my $k (keys %$entries) {
        my $msg = $entries->{$k};
        while ($msg =~ /$RE{net}{IPv4}/g) {
            push @ips, $&;
        }
    }
    my @u = sort { $a cmp $b } keys %{{ map { $_ => 1 } @ips }};
    $self->_log(debug => "Returning: " . join(", ", @u)) if @u;
    return \@u;
}

sub _remove_never_block_ips {
    my ($self, $ips) = @_;
    my %keep = map { $_ => 1 } @$ips;
    for my $ip (@$ips) {
        for my $cidr (@{$self->{conf}->{never_block_cidrs}}) {
            if (cidrlookup($ip, $cidr)) {
                $self->_log(info => "IP $ip is in $cidr; skipping");
                delete $keep{$ip};
                last;
            }
        }
    }
    return [ keys %keep ];
}

sub _remove_already_blocked_ips {
    my ($self, $ips) = @_;
    my @already = grep { $self->{blocked}{$_} } @$ips;
    $self->_log(debug => "Already blocked: " . join(',', @already)) if @already;
    return [ grep { !$self->{blocked}{$_} } @$ips ];
}

# -------------------- nftables --------------------
sub _add_ips_to_nft {
    my ($self, $ips) = @_;
    my $set   = $self->{conf}->{nft_set};
    my $tab   = $self->{conf}->{nft_family_table};
    my $fam   = $self->{conf}->{nft_table};
    my $ttl   = $self->{conf}->{blocking_time};

    @$ips = sort @$ips;
    for my $ip (@$ips) {
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
            eval { $self->_db_upsert_jailed_ip($ip, $exp) };
            $@ and $self->_log(error => "SQLite upsert failed for $ip: $@");
            $self->_log(info  => "Jailed $ip for ${ttl}s");
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
