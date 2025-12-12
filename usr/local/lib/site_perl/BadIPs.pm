package BadIPs;
use strict;
use warnings;
use feature 'state';

use Config::Tiny;
use File::Spec;
use File::Path qw(make_path);
use Time::HiRes qw(time sleep);
use POSIX qw(strftime);
use JSON qw(decode_json);
use DBI;
use DBD::Pg;  # PostgreSQL driver
use Log::Log4perl qw( get_logger );
use Log::Log4perl::MDC;
use Regexp::Common qw(net);
use Net::CIDR qw(cidrlookup);
use Sys::Hostname qw(hostname);
use File::ReadBackwards;
use Data::Dumper;
use LWP::UserAgent;
use LWP::Protocol::file;
use Digest::MD5 qw(md5_hex);
use Storable qw(dclone);

use threads;
use threads::shared;
use Thread::Queue;

$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 1;

my $log = get_logger("BadIPs") || die "You MUST initialize Log::Log4perl before using BadIPs module";

our $VERSION = '3.1.0';

# -------------------------------------------------------------------------
# Shared state for all threads
# -------------------------------------------------------------------------

# NOTE:
#   $shutdown => request to fully shut down the daemon.
#   $reload   => request to reload config and restart worker threads.
#
# Threads should treat either flag as "time to exit soon", but the main
# supervisor will distinguish how to proceed: exit vs restart workers.

my $shutdown :shared = 0;
my $reload   :shared = 0;

# Thread-safe queues (references are shared via globals; Thread::Queue
# handles internal synchronization)
my $ips_to_block_queue;
my $sync_to_central_db_queue;

# Random platitudes for shutdown message
my @PLATITUDES = (
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

# -------------------------------------------------------------------------
# Object structure:
#   conf_main, conf_dir, conf => hashref
#   threads => [ { name => ..., thread => threads::Thread } ]
#   blocked => { ip => expires_epoch }  (in-memory cache)
#   run_count => integer
# -------------------------------------------------------------------------

=head2 new

Description:
    Constructor for the BadIPs daemon supervisor object. It does not start
    any threads by itself; it only initializes configuration state.

Arguments:
    %args:
        conf_main  => string, path to main config file (default: /usr/local/etc/badips.conf)
        conf_dir   => string, path to conf.d directory (default: /usr/local/etc/badips.d)
        dry_run    => bool, if true, do not actually add IPs to nftables

Returns:
    Object instance (hashref blessed into BadIPs).

=cut
sub new {
    my ($class, %args) = @_;

    my $self = {
        conf_main  => $args{conf_main} // '/usr/local/etc/badips.conf',
        conf_dir   => $args{conf_dir}  // '/usr/local/etc/badips.d',
        conf       => {},
        dry_run    => $args{dry_run} ? 1 : 0,
        threads    => [],
        blocked    => {},     # ip => expires_epoch (in-memory view of nftables set)
        run_count  => 0,
        logconf    => $args{logconf} || 0,
        logconf_refresh_interval => $args{logconf_refresh_interval} || 5,
    };

    bless $self, $class;

    my $conf = $self->_load_config();
    $self->{conf} = $conf;

    $self->_auto_discover_sources();
    $self->_init_queues();
    $self->_refresh_static_nftables_sets();
    $self->_initial_load_blocked_ips();

    $log->info("BadIPs daemon instantiated");

    return $self;
}

=head2 run

Description:
    Main entry point. Installs signal handlers, starts worker threads,
    and runs the log-processing loop until shutdown is requested.

Arguments:
    (none) – uses configuration loaded in ->new.

Returns:
    1 on graceful shutdown; dies on fatal errors.

=cut

sub run {
    my ($self) = @_;

    $log->info("Starting BadIPs module run loop");

    $self->_install_signal_handlers();
    $self->_start_worker_threads();

    my $hb_at  = time() + ($self->{conf}->{heartbeat} // 60);  # Set initial heartbeat
    my %new_since_hb;
    my $read_journal_epoch = int(time());

    # Initial read window
    my $entries = $self->_read_all_sources(
        max_file_lines      => $self->{conf}->{max_file_tail_lines},
        read_journal_since  => time() - $self->{conf}->{initial_journal_lookback},
    );

    # Pretty harsh but necessary: monitor log4perl config file for changes
    my $logconf_mtime = ( stat($self->{logconf}) )[9] or die "Cannot stat logconf file '$self->{logconf}'";
    my $logconf_reload_epoch = 0;

    MAIN_LOOP:
    while (1) {
        # Check for shutdown
        if (_get_shutdown_flag()) {
            $log->info("Shutdown flag detected in main loop");
            last MAIN_LOOP;
        }

        # Check log4perl config change and set reload if needed
        my $current_logconf_mtime = ( stat($self->{logconf}) )[9] or die "Cannot stat logconf file '$self->{logconf}'";
        if ($current_logconf_mtime != $logconf_mtime) {
            $logconf_reload_epoch = int(time()) + $self->{logconf_refresh_interval};
            my $reload_dt = strftime("%Y-%m-%d %H:%M:%S", localtime($logconf_reload_epoch));
            $log->debug("Threads will reload at or after $reload_dt due to log4perl config file change");
            $logconf_mtime = $current_logconf_mtime;
        }
        if ( $logconf_reload_epoch && time() >= $logconf_reload_epoch ) {
            $log->info("Setting threads to reload due to log4perl config file change");
            _set_reload_flag();
            $logconf_reload_epoch = 0;
        }

        # Check for reload
        if (_get_reload_flag()) {
            $log->info("Reload flag detected in main loop, reloading configuration and restarting workers");
            $self->_handle_reload_request();
            # After reload, reset baseline heartbeat and journal cursor
            $hb_at              = time() + ($self->{conf}->{heartbeat} // 60);
            %new_since_hb       = ();
            $read_journal_epoch = int(time());
            $entries = $self->_read_all_sources(
                max_file_lines      => $self->{conf}->{max_file_tail_lines},
                read_journal_since  => time() - $self->{conf}->{initial_journal_lookback},
            );
            next MAIN_LOOP;
        }

        $self->{run_count}++;

        # 1) Process current log entries into IP events
        my $bad = {};
        $bad = $self->_bad_entries($entries) if $entries && keys %$entries;

        my $ip_data = [];
        $ip_data = $self->_remote_addresses($bad) if $bad && keys %$bad;

        # 2) Enqueue IPs for blocking
        for my $item (@$ip_data) {
            $ips_to_block_queue->enqueue({
                ip       => $item->{ip},
                source   => $item->{metadata}->{service}  || 'unknown',
                detector => $item->{metadata}->{detector} || 'unknown',
                line     => $item->{metadata}->{log_line},
            });
            $new_since_hb{$item->{ip}} = 1;
        }

        $log->debug("Run #$self->{run_count}: enqueued " . scalar(@$ip_data) . " IP(s) for blocking");

        # 3) Sleep & housekeeping
        sleep($self->{conf}->{sleep_time} // 2);
        $self->_remove_expired_ips();

        # 4) Heartbeat
        if (time() > $hb_at) {
            $hb_at = time() + ($self->{conf}->{heartbeat} // 60);
            $self->heartbeat_info(
                heartbeat_interval => $self->{conf}->{heartbeat},
                new_since_hb       => \%new_since_hb,
                next_hb_at        => $hb_at,
            );
            %new_since_hb = ();
        }

        # 5) Re-read logs
        my $current_read_journal_epoch = int(time());
        $entries = $self->_read_all_sources(
            max_file_lines      => $self->{conf}->{max_file_tail_lines},
            read_journal_since  => $read_journal_epoch,
        );
        $read_journal_epoch = $current_read_journal_epoch;
    }

    # Graceful shutdown
    $log->info("Main loop exiting, initiating graceful shutdown of worker threads and queues");
    $self->_shutdown_and_join_workers();

    my $goodbye = "All threads joined, exiting gracefully. ";
    my $idx = int(rand(scalar(@PLATITUDES)));
    $goodbye .= $PLATITUDES[$idx];
    $log->info($goodbye);

    $log->info("The End.");
    return 1;
}

# -------------------------------------------------------------------------
# Signal handling and shared flags
# -------------------------------------------------------------------------

=head2 _install_signal_handlers

Description:
    Install signal handlers for TERM/INT/QUIT (shutdown) and HUP (reload).
    The handlers are intentionally minimal: they only set shared flags.

Arguments:
    (method) $self – object instance.

Returns:
    Nothing.

=cut

sub _install_signal_handlers {
    my ($self) = @_;

    $SIG{TERM} = sub {
        $log->info("SIGTERM received, requesting shutdown");
        _set_shutdown_flag();
    };
    $SIG{INT} = sub {
        $log->info("SIGINT received, requesting shutdown");
        _set_shutdown_flag();
    };
    $SIG{QUIT} = sub {
        $log->info("SIGQUIT received, requesting shutdown");
        _set_shutdown_flag();
    };
    $SIG{HUP} = sub {
        $log->info("SIGHUP received, requesting reload");
        _set_reload_flag();
    };
}

=head2 _set_shutdown_flag

Description:
    Helper to set the shared shutdown flag.

Arguments:
    (none)

Returns:
    Nothing.

=cut

sub _set_shutdown_flag {
    {
        lock($shutdown);
        $shutdown = 1;
    }
}

=head2 _get_shutdown_flag

Description:
    Helper to safely read the shared shutdown flag.

Arguments:
    (none)

Returns:
    Boolean – current shutdown flag (0 or 1).

=cut

sub _get_shutdown_flag {
    lock($shutdown);
    return $shutdown ? 1 : 0;
}

=head2 _set_reload_flag

Description:
    Helper to set the shared reload flag.

Arguments:
    (none)

Returns:
    Nothing.

=cut

sub _set_reload_flag {
    {
        lock($reload);
        $reload = 1;
    }
}

=head2 _clear_reload_flag

Description:
    Helper to clear the shared reload flag after a reload operation.

Arguments:
    (none)

Returns:
    Nothing.

=cut

sub _clear_reload_flag {
    {
        lock($reload);
        $reload = 0;
    }
}

=head2 _get_reload_flag

Description:
    Helper to safely read the shared reload flag.

Arguments:
    (none)

Returns:
    Boolean – current reload flag (0 or 1).

=cut

sub _get_reload_flag {
    lock($reload);
    return $reload ? 1 : 0;
}

# -------------------------------------------------------------------------
# Configuration + detectors
# -------------------------------------------------------------------------

=head2 _load_config

Description:
    Load and merge configuration from the main config and any conf.d
    files. Host-specific sections (host:<hostname>) override global
    values. Also sets sensible defaults for missing keys.

Arguments:
    (method) $self – object instance.

Returns:
    Hashref of effective configuration suitable for sharing to worker
    threads (e.g. via dclone).

=cut

sub _load_config {
    my ($self) = @_;

    my $host = (split(/\./, hostname()))[0];

    my @files;
    push @files, $self->{conf_main} if -f $self->{conf_main};
    if (-d $self->{conf_dir}) {
        opendir my $dh, $self->{conf_dir};
        my @extra = sort grep {
            /\.conf\z/ && -f File::Spec->catfile($self->{conf_dir}, $_)
        } readdir $dh;
        closedir $dh;
        push @files, map { File::Spec->catfile($self->{conf_dir}, $_) } @extra;
    }

    my %accum;
    for my $f (@files) {
        my $c = Config::Tiny->read($f);
        next unless $c;

        if (my $g = $c->{global}) {
            %accum = (%accum, %$g);
        }
        if (my $h = $c->{"host:$host"}) {
            %accum = (%accum, %$h);
        }
    }

    # Core defaults
    $accum{blocking_time}             //= 86400 * 8;
    $accum{sleep_time}                //= 2;
    $accum{heartbeat}                 //= 60;
    $accum{extra_time}                //= 120;
    $accum{initial_journal_lookback}  //= 300;
    $accum{journal_units}             //= 'ssh';
    $accum{bad_conn_patterns}         //= 'Failed password for invalid user,Failed password for root,Failed password for,Failed password for .* from,Failed password for .* from .* port';
    $accum{never_block_cidrs}         //= '';
    $accum{always_block_cidrs}        //= '';
    $accum{log_level}                 //= 'INFO';
    $accum{nft_table}                 //= 'inet';
    $accum{nft_family_table}          //= 'filter';
    $accum{nft_set}                   //= 'badipv4';
    $accum{file_sources}              //= '';
    $accum{max_file_tail_lines}       //= 2000;
    $accum{auto_mode}                 //= 1;

    # Public blocklist defaults
    $accum{public_blocklist_urls}     //= '';
    $accum{public_blocklist_refresh}  //= 900;
    $accum{public_blocklist_use_cache}//= 1;
    $accum{public_blocklist_cache_path}//= '/var/cache/badips';

    # Threading + queue defaults
    $accum{ips_to_block_queue_max}                 //= 5000;
    $accum{sync_to_central_db_queue_max}           //= 10000;
    $accum{sync_to_central_db_queue_critical_time} //= 300;
    $accum{central_db_batch_size}                  //= 1000;
    $accum{central_db_batch_timeout}               //= 5;
    $accum{pull_min_interval}                      //= 2;
    $accum{pull_step_interval}                     //= 4;
    $accum{pull_initial_interval}                  //= 20;
    $accum{pull_max_interval}                      //= 180;
    $accum{failover_log}                           //= '/var/lib/bad_ips/failover.log';
    $accum{failover_enabled}                       //= 1;
    $accum{graceful_shutdown_timeout}              //= 300;

    # PostgreSQL configuration
    $accum{db_type}     //= 'postgresql';
    $accum{db_host}     //= 'localhost';
    $accum{db_port}     //= 5432;
    $accum{db_name}     //= 'bad_ips';
    $accum{db_user}     //= 'bad_ips_hunter';
    $accum{db_password} //= '';
    $accum{db_ssl_mode} //= 'disable';

    # Normalize comma lists
    $accum{journal_units}      = _csv_to_array($accum{journal_units});
    $accum{bad_conn_patterns}  = _csv_to_array($accum{bad_conn_patterns});
    $accum{never_block_cidrs}  = _csv_to_array($accum{never_block_cidrs});
    $accum{always_block_cidrs} = _csv_to_array($accum{always_block_cidrs});
    $accum{file_sources}       = _csv_to_array($accum{file_sources});
    $accum{public_blocklist_urls} = _csv_to_array($accum{public_blocklist_urls});

    return \%accum;
}

=head2 _csv_to_array

Description:
    Helper to split a comma-separated string into an arrayref of trimmed
    entries. Empty or undefined input returns an empty arrayref.

Arguments:
    $s – string or undef.

Returns:
    Arrayref of strings.

=cut

sub _csv_to_array {
    my ($s) = @_;
    return [] unless defined $s;
    my @x = map {
        my $t = $_;
        $t =~ s/^\s+|\s+$//g;
        $t;
    } split(/\s*,\s*/, $s);
    return \@x;
}

=head2 _auto_discover_sources

Description:
    Auto-discover log sources and patterns based on detector config in
    conf.d. For now this reuses the existing logic to build:
        conf->{journal_units}
        conf->{file_sources}
        conf->{compiled_patterns}

Arguments:
    (method) $self – object instance.

Returns:
    Nothing; modifies $self->{conf} in-place.

=cut

sub _auto_discover_sources {
    my ($self) = @_;

    # For now we keep the same pattern you had:
    # - If no detectors configured, compile static patterns.
    # - Otherwise, treat detectors in conf.d.
    #
    # Later, this logic can be moved into SW::BadIPs::Config or
    # SW::BadIPs::Detector.

    my $conf = $self->{conf};

    # If no auto_mode, just compile patterns and bail
    unless ($conf->{auto_mode}) {
        my @compiled = map { eval { qr/$_/ } || () } @{$conf->{bad_conn_patterns} || []};
        $conf->{compiled_patterns} = \@compiled;
        return;
    }

    # Basic behavior: we will just compile bad_conn_patterns and keep
    # journal_units / file_sources from config.
    my @compiled = map { eval { qr/$_/ } || () } @{$conf->{bad_conn_patterns} || []};
    $conf->{compiled_patterns} = \@compiled;

    # If nothing is configured, default to "ssh"
    $conf->{journal_units} ||= _csv_to_array('ssh');

    my $units_msg = @{$conf->{journal_units}} ? join(", ", @{$conf->{journal_units}}) : '(none)';
    my $files_msg = @{$conf->{file_sources}}   ? join(", ", @{$conf->{file_sources}})   : '(none)';

    $log->info("AUTO(config): units=$units_msg files=$files_msg patterns=" . scalar(@compiled));
}

=head2 _report_config

Description:
    Build a human-readable summary of the current configuration, useful
    for logs or test mode.

Arguments:
    (method) $self – object instance.

Returns:
    String with configuration details.

=cut

sub _report_config {
    my ($self) = @_;
    my $c = $self->{conf};

    my $units = @{$c->{journal_units} || []} ? join(", ", @{$c->{journal_units}}) : '(none)';
    my $files = @{$c->{file_sources}  || []} ? join(", ", @{$c->{file_sources}})  : '(none)';

    my $pats  = $c->{compiled_patterns} && @{$c->{compiled_patterns}}
        ? scalar(@{$c->{compiled_patterns}})
        : scalar(@{$c->{bad_conn_patterns} || []});

    my @txt;
    push @txt, "bad_ips configuration:";
    push @txt, "  nft: table=$c->{nft_table} family_table=$c->{nft_family_table} set=$c->{nft_set}";
    push @txt, "  block_time=$c->{blocking_time}s sleep=$c->{sleep_time}s heartbeat=$c->{heartbeat}s";
    push @txt, "  journal_units: $units";
    push @txt, "  file_sources:  $files";
    push @txt, "  patterns:      $pats compiled";
    push @txt, "  db: $c->{db_type} on $c->{db_host}:$c->{db_port}/$c->{db_name}";
    push @txt, "  log_level: $c->{log_level}";
    push @txt, "  auto_mode: " . ($c->{auto_mode} ? 1 : 0);
    push @txt, "  dry_run:   " . ($self->{dry_run} ? 1 : 0);

    return join("\n", @txt) . "\n";
}

=head2 test_config

Description:
    Helper to validate configuration and return a summary + status.

Arguments:
    (method) $self – object instance.

Returns:
    (ok, status, report):
        ok     => 1 or 0
        status => 'ok' or 'invalid'
        report => string summary of config and any errors

=cut

sub test_config {
    my ($self) = @_;

    # Reload and recompute everything
    $self->{conf} = $self->_load_config();
    $self->_auto_discover_sources();
    my $report = $self->_report_config();

    my @errs;
    push @errs, "Missing nft set name" unless $self->{conf}->{nft_set};
    push @errs, "No patterns compiled"
        unless $self->{conf}->{compiled_patterns} && @{$self->{conf}->{compiled_patterns}};

    if (!@{$self->{conf}->{journal_units} || []} && !@{$self->{conf}->{file_sources} || []}) {
        push @errs, "No journald units or file sources configured";
    }

    if (@errs) {
        $report .= "\nErrors:\n  - " . join("\n  - ", @errs) . "\n";
        return (0, "invalid", $report);
    } else {
        $report .= "\nStatus: OK\n";
        return (1, "ok", $report);
    }
}

# -------------------------------------------------------------------------
# Queue initialization + worker thread orchestration
# -------------------------------------------------------------------------

=head2 _init_queues

Description:
    Initialize the global Thread::Queue instances used by all threads.
    Safe to call on startup and during reload; it overwrites the global
    queue variables with new queue objects.

Arguments:
    (method) $self – object instance (not strictly used, but kept for
                     symmetry).

Returns:
    Nothing.

=cut

sub _init_queues {
    my ($self) = @_;

    $ips_to_block_queue       = Thread::Queue->new();
    $sync_to_central_db_queue = Thread::Queue->new();

    $log->debug("Initialized thread-safe queues");
}

=head2 _start_worker_threads

Description:
    Start all worker threads with cloned configuration. No $self reference
    is passed into threads; they only receive a deep-cloned config.

Arguments:
    (method) $self – object instance.

Returns:
    Nothing; updates $self->{threads} with thread info.

=cut

sub _start_worker_threads {
    my ($self) = @_;

    my %workers = ( 
        nft_blocker       => \&_worker_nft_blocker,
        central_db_sync   => \&_worker_central_db_sync,
        pull_global_blocks=> \&_worker_pull_global_blocks,
        public_blocklists => \&_worker_public_blocklists,
    );

    $self->{threads} = [];

    for my $name (sort keys %workers) {  # Start order is irrelevant because we are using queues
        my $conf_clone = dclone($self->{conf});  # Do not send full $self into thread!!!!
        $log->info("Starting worker thread: $name");
        my $thr;
        eval {
            $thr = threads->create($workers{$name}, (conf => $conf_clone, thread_name => $name));
        };
        if ($@) {
            $log->error("Failed to start worker thread $name: $@");
            $log->die("Cannot continue without all worker threads running");
        }
        push @{$self->{threads}}, { name => $name, thread => $thr };
    }

    $log->info("All worker threads started");
}

=head2 _shutdown_and_join_workers

Description:
    Used on final shutdown. Sets queue end markers, waits for queues to
    drain, and joins all worker threads.

Arguments:
    (method) $self – object instance.

Returns:
    Nothing.

=cut

sub _shutdown_and_join_workers {
    my ($self) = @_;

    # We assume $shutdown flag is already set by signal or caller.

    $self->_drain_queues();

    # Log the threads to be joined
    my @thread_info;
    for my $wt (@{$self->{threads} || []}) {
        my $name = $wt->{name};
        my $thread_id = $wt->{thread}->tid() || 'unknown';
        push @thread_info, "$name (TID: $thread_id)";
    }
    $log->info("Joining worker threads: " . join(", ", @thread_info));

    my $graceful_timeout = $self->{conf}->{graceful_shutdown_timeout} || 300;
    for my $wt (@{$self->{threads} || []}) {
        my $name = $wt->{name};
        my $thr  = $wt->{thread};
        next unless $thr;
        $log->info("Joining worker thread $name");
        my $join_result = $self->_join_with_timeout(
                thread  => $thr,
                name    => $name,
                timeout => $graceful_timeout,
            );
        if (!$join_result) {
            $log->error("Worker thread $name did not exit in time, detaching");
            eval { $thr->detach() };
            if ($@) {
                $log->error("Failed to detach thread $name: $@");
                $log->logdie("Cannot continue with stuck worker threads!!!!  Please investigate.");
            }
        } else {
            $log->info("Worker thread $name joined successfully");
        }
    }

    $self->{threads} = [];
}

=head2 _handle_reload_request

Description:
    Handle an in-process reload request:
        - End queues to let workers exit.
        - Join existing worker threads.
        - Reload configuration.
        - Re-init queues and static nftables sets.
        - Restart worker threads with the new configuration.
        - Clear reload flag.

Arguments:
    (method) $self – object instance.

Returns:
    Nothing.

=cut

sub _handle_reload_request {
    my ($self) = @_;

    # 1) Request existing workers to exit via queue end
    $log->info("Reload: ending queues to allow workers to exit");
    $ips_to_block_queue->end()       if $ips_to_block_queue;
    $sync_to_central_db_queue->end() if $sync_to_central_db_queue;

    # 2) Join worker threads
    for my $wt (@{$self->{threads} || []}) {
        my $name = $wt->{name};
        my $thr  = $wt->{thread};
        next unless $thr;
        $log->info("Reload: joining worker thread $name");
        my $join_result = $self->_join_with_timeout(
                thread  => $thr,
                name    => $name,
                timeout => $self->{conf}->{graceful_shutdown_timeout} || 30,
            );
        if (!$join_result) {
            $log->error("Reload: worker thread $name did not exit in time, detaching");
            eval { $thr->detach() };
            if ($@) {
                $log->error("Reload: failed to detach thread $name: $@");
                $log->logdie("Cannot continue with stuck worker threads!!!!  Please investigate.");
            }
        } else {
            $log->info("Reload: worker thread $name joined successfully");
        }
    }
    $self->{threads} = [];

    # 3) Reload config
    eval {
        $self->{conf} = $self->_load_config();
        $self->_auto_discover_sources();
        $self->_refresh_static_nftables_sets();
        $log->info("Reload: new configuration loaded:\n" . $self->_report_config());
    };
    if ($@) {
        $log->info("Reload failed: $@ (continuing with previous configuration)");
    }

    # 4) Re-init queues and restart workers
    $self->_init_queues();
    $self->_start_worker_threads();

    # 5) Clear reload flag
    _clear_reload_flag();
}

=head2 _join_with_timeout

Description:
    Helper to join a thread with a timeout. If the thread does not
    exit within the timeout then returns 0; otherwise returns 1.

Arguments:
    %args (
        thread  => threads::Thread object (required)
        name    => string, worker name for logging (optional but recommended)
        timeout => integer, seconds before giving up (default: 30)
    )
Returns:
    1 if joined successfully, 0 if detached due to timeout.

=cut
sub _join_with_timeout {
    # my ($thr, $name, $timeout) = @_;
    my ($self, %args) = @_;
    my $thr           = $args{thread}  or $log->info("No thread provided to _join_with_timeout") && return 0;
    my $timeout       = $args{timeout} || 30;
    my $start         = time;
    my $name          = $args{name}    || 'unknown';

    while (1) {
        if ($thr->is_joinable) {
            eval { $thr->join() };
            if ($@) {
                $log->error("Thread $name join died: $@");
            }
            return 1;
        }

        if (time - $start > $timeout) {
            $log->error("Worker $name did not exit within ${timeout}s");
            return 0;
        }

        Time::HiRes::usleep(500_000);  # Sleep 0.5s
    }
}


# -------------------------------------------------------------------------
# DB helpers (PostgreSQL only)
# -------------------------------------------------------------------------

=head2 _create_pg_connection

Description:
    Create a new PostgreSQL DBI connection using the given configuration.

Arguments:
    %args:
        conf => hashref with keys:
            db_host, db_port, db_name, db_user, db_password, db_ssl_mode

Returns:
    $dbh – DBI handle on success, or undef on failure.

=cut

sub _create_pg_connection {
    my (%args) = @_;
    my $conf = $args{conf} || {};

    return undef unless $conf->{db_host} && defined $conf->{db_password};

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

    # Do a quick test query
    eval {
        $dbh->do("SELECT 1");
    };

    if ($@) {
        $log->info("Thread DB test query failed: $@");
        return undef;
    }

    return $dbh;
}

=head2 _db_upsert_blocked_ip_batch

Description:
    Insert or update a batch of blocked IP records into the jailed_ips
    table in PostgreSQL using a single multi-row INSERT ... ON CONFLICT.

Arguments:
    %args:
        dbh   => DBI handle
        conf  => hashref with config (used for hostname)
        batch => arrayref of items, each:
                    {
                        ip         => 'x.x.x.x',
                        expires_at => epoch,
                        source     => 'service',
                        detector   => 'detector',
                        log_line   => 'original line',
                    }

Returns:
    Nothing; dies on DB errors.

=cut

sub _db_upsert_blocked_ip_batch {
    my (%args) = @_;
    my $dbh   = $args{dbh}   or die "_db_upsert_blocked_ip_batch: dbh required";
    my $conf  = $args{conf}  || {};
    my $batch = $args{batch} || [];

    return unless @$batch;

    my $hostname = $conf->{hostname} || hostname();
    chomp $hostname;

    my $sql = "INSERT INTO jailed_ips (
        ip, originating_server, originating_service, detector_name,
        pattern_matched, matched_log_line,
        first_blocked_at, last_seen_at, expires_at, block_count
    ) VALUES ";

    my @placeholders;
    my @values;

    my $now = int(time());

    for my $item (@$batch) {
        push @placeholders, "(?, ?, ?, ?, ?, ?, ?, ?, ?, 1)";
        push @values,
            $item->{ip},
            $hostname,
            $item->{source}   || 'unknown',
            $item->{detector} || 'unknown',
            'unknown',  # pattern_matched
            substr($item->{log_line} || '', 0, 500),
            $now,
            $now,
            int($item->{expires_at});
    }

    $sql .= join(", ", @placeholders);
    $sql .= " ON CONFLICT(ip, originating_server) DO UPDATE SET
        last_seen_at   = excluded.last_seen_at,
        expires_at     = excluded.expires_at,
        block_count    = jailed_ips.block_count + 1,
        pattern_matched= excluded.pattern_matched,
        matched_log_line = excluded.matched_log_line";

    $log->debug("central_db_sync_thread: executing batch INSERT with " . scalar(@$batch) . " rows");
    my $sth = $dbh->prepare($sql);
    $sth->execute(@values);
}

# -------------------------------------------------------------------------
# Worker threads (no $self; only cloned %conf)
# -------------------------------------------------------------------------

=head2 _worker_nft_blocker

Description:
    Worker thread that consumes IP items from ips_to_block_queue and
    applies them to the nftables set with timeouts.

Arguments:
    %args:
        conf => hashref, cloned configuration for this thread
            conf keys used:
                nft_set
                nft_family_table
                nft_table
                blocking_time
                dry_run

Returns:
    Nothing (thread exits when shutdown or reload is requested).

=cut

sub _worker_nft_blocker {
    my (%args)  = @_;
    my $conf    = $args{conf} || {};
    my $set     = $conf->{nft_set};
    my $tab     = $conf->{nft_family_table};
    my $fam     = $conf->{nft_table};
    my $ttl     = $conf->{blocking_time} || 3600;
    my $dry_run = $conf->{dry_run} ? 1 : 0;
    my $thread_name = $args{thread_name} ||  (caller(0))[3];

    Log::Log4perl::MDC->put("THREAD" => $thread_name);

    my %blocked_in_thread;

    $log->info("nft_blocker_thread started (table=$fam, family_table=$tab, set=$set, ttl=$ttl)");

    while (!_get_shutdown_flag() && !_get_reload_flag()) {
        my $item = $ips_to_block_queue->dequeue();
        last if ( ! defined $item );  # Probably queue has ended and _get_shutdown_flag() or _get_reload_flag() is set

        next if _should_skip_ip(%args, item => $item, blocked => \%blocked_in_thread, conf => $conf);

        my $res = _nft_block_ip(
            ip   => $item->{ip},
            ttl  => $ttl,
            conf => $conf,
        );

        if ($res->{ok}) {
            $blocked_in_thread{$item->{ip}} = $res->{expires};
            _enqueue_central_db_update(item => $item, expires => $res->{expires}); # PRetty much fire-and-forget
        } else {
            $log->debug("NFT block failed but this is probably not an actual error for $item->{ip}: $res->{err}");
        }
    }
    $log->info("nft_blocker_thread ready to be joined");
    Log::Log4perl::MDC->remove("THREAD");

    return 1;
}

=head2 _should_skip_ip

Description:
    Helper to determine if an IP should be skipped for blocking.

Arguments:
    %args:
        item    => hashref with keys:
                        ip         => 'x.x.x.x',
        blocked => hashref of already blocked IPs in this thread
Returns:
    1 if the IP should be skipped, 0 otherwise.
=cut

sub _should_skip_ip {
    my (%args) = @_;
    my $item    = $args{item};
    my $blocked = $args{blocked} || {};
    my $conf    = $args{conf} || {};

    my $ip = $item->{ip};
    if (!defined $ip) {
        $log->debug("Skipping item with no IP");
        return 1;
    }

    # Check if IP/block should never be blocked
    if (_is_never_block_ip(ip => $ip, conf => $conf)) {
        $log->debug("Skipping IP $ip: in never_block_cidrs");
        return 1;
    }    

    # Already blocked in this thread?
    if (exists $blocked->{$ip}) {
        $log->debug("Skipping IP $ip: already blocked in this thread");
        return 1;
    }

    return 0;
}

=head2 _enqueue_central_db_update

Description:
    Helper to enqueue a blocked IP item to the sync_to_central_db_queue.
Arguments:
    %args:
        item    => hashref with keys:
                        ip         => 'x.x.x.x',
                        source     => 'service',
                        detector   => 'detector',
                        line       => 'original line',
        expires => epoch time when block expires
Returns:
    1 on success, 0 on failure.
=cut
sub _enqueue_central_db_update {
    my (%args) = @_;
    my $item    = $args{item};
    my $expires = $args{expires};

    my $db_item = {
        ip         => $item->{ip},
        expires_at => $expires,
        source     => $item->{source},
        detector   => $item->{detector},
        log_line   => $item->{line},
    };

    eval {
        $sync_to_central_db_queue->enqueue($db_item);
    };
    if ($@) {
        $log->info("Failed to enqueue item to central_db_sync_queue.  Could be full or ended: $@");
        return 0;
    }
    return 1;
}

=head2 _nft_block_ip

Description:
    Helper to block a single IP in nftables with a timeout.

Arguments:
    %args:
        ip   => string, IP address to block
        ttl  => integer, blocking time in seconds
        conf => hashref, configuration with nftables details
Returns:
    Hashref with:
        ok      => 1 on success, 0 on failure
        expires => epoch time when block expires (on success)
        out     => command output (on success)
        err     => error message (on failure)
        rc      => return code (on failure)
=cut
sub _nft_block_ip {
    my (%args) = @_;
    my $ip     = $args{ip};
    my $ttl    = $args{ttl};
    my $conf   = $args{conf};

    my $cmd = "nft add element $conf->{nft_table} $conf->{nft_family_table} $conf->{nft_set} { $ip timeout ${ttl}s }";

    if ($conf->{dry_run}) {
        my $exp = time() + $ttl;
        return { ok => 1, expires => $exp, dry_run => 1 };
    }

    my ($out, $rc);
    eval {
        $out = qx($cmd 2>&1);
        $rc  = $? >> 8;
    };
    if ($@) {
        return { ok => 0, err => "Command execution ( command: $cmd ) failed with output ( $out ).  Eval error: $@",
                rc => -1 };
    }

    if ($rc == 0) {
        my $exp = time() + $ttl;
        return { ok => 1, expires => $exp, out => $out };
    }

    return { ok => 0, err => $out, rc => $rc };
}

=head2 _worker_central_db_sync

Description:
    Worker thread that consumes items from sync_to_central_db_queue and
    writes them to the central PostgreSQL database in batches.

    There is a some random sleep between dequeues to avoid thundering
    herd issues on the DB.  This is NOT critical path, so a few seconds
    of delay is acceptable.

Arguments:
    %args:
        conf => hashref, cloned configuration for this thread

Returns:
    Nothing.

=cut

sub _worker_central_db_sync {
    my (%args) = @_;
    my $conf          = $args{conf} || {};
    my $batch_timeout = $conf->{central_db_batch_timeout} || 5;
    my $batch_size    = $conf->{central_db_batch_size} || 50;
    my $thread_name = $args{thread_name} ||  (caller(0))[3];

    Log::Log4perl::MDC->put("THREAD" => $thread_name);

    my $dbh = _create_pg_connection(conf => $conf);
    unless ($dbh) {
        $log->warn("central_db_sync_thread: no database connection, exiting");
        return;
    }

    $log->info("central_db_sync_thread started (batch_size=$batch_size)");

    while (!_get_shutdown_flag() && !_get_reload_flag()) {
        my $item = $sync_to_central_db_queue->dequeue();

        # if item is undef, then the queue is ended; exit thread
        if ( ! defined $item ) {
            $log->info("central_db_sync_thread: queue appears to have ended, exiting");
            last;
        }

        my @batch = ($item);
        my $batch_start = time();
        while ( (@batch < $batch_size) && (time() - $batch_start < $batch_timeout) ) {
            my $next = $sync_to_central_db_queue->dequeue_nb();
            push @batch, $next if defined $next;
        }

        eval {
            _db_upsert_blocked_ip_batch(
                dbh   => $dbh,
                conf  => $conf,
                batch => \@batch,
            );
        };
        if ($@) {
            $log->info("Central DB batch INSERT failed: $@; requeueing items");
            $sync_to_central_db_queue->enqueue(@batch);
            sleep 10;
        } else {
            my @ips = map { $_->{ip} } @batch;
            $log->info("Synced or updated " . scalar(@batch) . " IP" . (scalar(@batch) == 1 ? '' : 's') .
                       " to central DB: " . join(", ", @ips));
        }
    }

    $dbh->disconnect() if $dbh;
    $log->info("central_db_sync_thread ready to be joined");
    Log::Log4perl::MDC->remove("THREAD");

    return 1;
}

=head2 _worker_pull_global_blocks

Description:
    Worker thread that periodically polls the central DB for blocks
    originating from other servers and enqueues them to be applied
    locally.

Arguments:
    %args:
        conf => hashref, cloned configuration for this thread

Returns:
    Nothing.

=cut

sub _worker_pull_global_blocks {
    my (%args) = @_;
    my $conf = $args{conf} || {};
    my $thread_name = $args{thread_name} ||  (caller(0))[3];

    Log::Log4perl::MDC->put("THREAD" => $thread_name);    

    my $dbh = _create_pg_connection(conf => $conf);
    unless ($dbh) {
        $log->warn("pull_global_blocks_thread: no database connection, exiting");
        return;
    }

    $log->info("pull_global_blocks_thread started");

    my $min_interval  = $conf->{pull_min_interval};
    my $pull_interval = $conf->{pull_initial_interval};
    my $max_interval  = $conf->{pull_max_interval};
    my $step          = $conf->{pull_step_interval};
    my $last_check    = time();
    my $hostname      = hostname();

    while (!_get_shutdown_flag() && !_get_reload_flag()) {
        sleep $pull_interval;
        last if _get_shutdown_flag() || _get_reload_flag();

        my $new_blocks = 0;

        eval {
            my $sth = $dbh->prepare(
                "SELECT ip, originating_server, originating_service, detector_name
                 FROM jailed_ips
                 WHERE originating_server != ?
                 AND last_seen_at > ?"
            );
            $sth->execute($hostname, int($last_check));

            while (my $row = $sth->fetchrow_hashref) {
                $new_blocks++;
                $ips_to_block_queue->enqueue({
                    ip       => $row->{ip},
                    source   => "central_db:$row->{originating_server}",
                    detector => $row->{detector_name} || 'global_sync',
                    line     => undef,
                });
            }

            $last_check = time();
        };
        if ($@) {
            $log->info("pull_global_blocks_thread: query failed: $@");
            sleep 10;
            next;
        }

        if ($new_blocks > 0) {
            $log->info("pull_global_blocks_thread: pulled $new_blocks new blocks from central DB");
            $pull_interval = $min_interval;
        } else {
            $pull_interval = $pull_interval + $step;
            $pull_interval = $max_interval if $pull_interval > $max_interval;
        }
    }

    $dbh->disconnect() if $dbh;
    $log->info("pull_global_blocks_thread ready to be joined");
    Log::Log4perl::MDC->remove("THREAD");

    return 1;
}

=head2 _worker_public_blocklists

Description:
    Worker thread that periodically fetches public blocklists (e.g.
    Spamhaus) from configured URLs, using conditional GETs based on
    ETag/If-Modified-Since and a local cache. Extracted IPs and
    IPv4/CIDRs are enqueued to ips_to_block_queue.

Arguments:
    %args:
        conf => hashref, cloned configuration for this thread

Returns:
    Nothing.

=cut

sub _worker_public_blocklists {
    my (%args) = @_;
    my $conf = $args{conf} || {};
    my $thread_name = $args{thread_name} ||  (caller(0))[3];

    Log::Log4perl::MDC->put("THREAD" => $thread_name);    

    my $urls       = $conf->{public_blocklist_urls} || [];
    my $interval   = $conf->{public_blocklist_refresh} || 3600;
    my $use_cache  = defined $conf->{public_blocklist_use_cache}
                   ? $conf->{public_blocklist_use_cache}
                   : 1;
    my $cache_path = $conf->{public_blocklist_cache_path} || '/var/cache/badips';

    $log->info("public_blocklist_thread started");

    if ($use_cache && ! -d $cache_path) {
        eval { make_path($cache_path) };
        if ($@) {
            $log->warn("public_blocklist_thread: failed to create cache dir $cache_path: $@");
            $use_cache = 0;
        }
    }

    unless (@$urls) {
        $log->info("public_blocklist_thread: no public blocklist URLs configured; exiting");
        return;
    }

    my $ua = LWP::UserAgent->new(
        timeout  => 10,
        agent    => "BadIPs/3.0",
        ssl_opts => { verify_hostname => 1 },
        max_size => 5_000_000,
    );

    while (!_get_shutdown_flag() && !_get_reload_flag()) {

        URL:
        for my $url (@$urls) {
            next URL unless $url;
            $log->info("public_blocklist_thread: processing source $url");

            my $url_md5    = md5_hex($url);
            my $cache_file = "$cache_path/blocklist_$url_md5.txt";
            my $etag_file  = "$cache_path/blocklist_$url_md5.etag";
            my $lm_file    = "$cache_path/blocklist_$url_md5.lastmod";

            my ($etag, $lastmod);

            if ($use_cache && -f $etag_file) {
                if (open my $fh, '<', $etag_file) {
                    local $/;
                    $etag = <$fh>;
                    close $fh;
                    chomp($etag) if $etag;
                }
            }
            if ($use_cache && -f $lm_file) {
                if (open my $fh, '<', $lm_file) {
                    local $/;
                    $lastmod = <$fh>;
                    close $fh;
                    chomp($lastmod) if $lastmod;
                }
            }

            my $content;
            my $cache_is_fresh = 0;

            # Cache freshness check
            if ($use_cache && -f $cache_file) {
                my $mtime = (stat($cache_file))[9] || 0;
                my $age   = time() - $mtime;
                if ($age < $interval) {
                    $cache_is_fresh = 1;
                    $log->info("public_blocklist_thread: using fresh cached blocklist $cache_file (age=${age}s)");
                    $content = do {
                        local $/;
                        open my $fh, '<', $cache_file or do {
                            $log->warn("public_blocklist_thread: could not read cache file $cache_file: $!");
                            undef;
                        };
                        <$fh>;
                    };
                } else {
                    $log->info("public_blocklist_thread: cache stale for $url (age=${age}s), performing conditional HTTP GET");
                }
            }

            # Conditional GET if needed
            if (!$content) {
                my %headers;
                $headers{'If-None-Match'}     = $etag    if defined $etag    && length $etag;
                $headers{'If-Modified-Since'} = $lastmod if defined $lastmod && length $lastmod;

                $log->info("public_blocklist_thread: sending GET $url with headers: " . Dumper(\%headers));
                my $response = $ua->get($url, %headers);

                if ($response->code == 304) {
                    $log->info("public_blocklist_thread: 304 Not Modified for $url, using cached content");
                    $content = do {
                        local $/;
                        open my $fh, '<', $cache_file or do {
                            $log->warn("public_blocklist_thread: cache missing for $url despite 304; skipping");
                            next URL;
                        };
                        <$fh>;
                    };
                }
                elsif ($response->is_success) {
                    $content = $response->decoded_content;
                    if ($use_cache) {
                        if (open my $fh, '>', $cache_file) {
                            print {$fh} $content;
                            close $fh;
                        }
                        if (my $new_etag = $response->header('ETag')) {
                            if (open my $efh, '>', $etag_file) {
                                print {$efh} $new_etag;
                                close $efh;
                                $log->info("public_blocklist_thread: saved ETag for $url: $new_etag");
                            }
                        }
                        if (my $new_lm = $response->header('Last-Modified')) {
                            if (open my $lfh, '>', $lm_file) {
                                print {$lfh} $new_lm;
                                close $lfh;
                                $log->info("public_blocklist_thread: saved Last-Modified for $url: $new_lm");
                            }
                        }
                        $log->info("public_blocklist_thread: updated cache for $url");
                    }
                }
                else {
                    $log->warn("public_blocklist_thread: failed to fetch $url: " . $response->status_line);
                    if ($use_cache && -f $cache_file) {
                        $log->warn("public_blocklist_thread: using stale cache for $url due to error");
                        $content = do {
                            local $/;
                            open my $fh, '<', $cache_file;
                            <$fh>;
                        };
                    } else {
                        next URL;
                    }
                }
            }

            my %seen;
            while ($content =~ /($RE{net}{IPv4})(?:\/(\d{1,2}))?/g) {
                my $ip   = $1;
                my $mask = $2;
                my $entry = defined $mask ? "$ip/$mask" : $ip;
                $seen{$entry}++;
            }

            $log->info("public_blocklist_thread: blocklist ($url) contains " . scalar(keys %seen) . " entries");

            for my $entry (keys %seen) {
                next if _is_never_block_ip(ip => $entry, conf => $conf);

                $ips_to_block_queue->enqueue({
                    ip       => $entry,
                    source   => 'public_blocklist',
                    detector => $url,
                    line     => undef,
                });
            }
        }

        for (1 .. $interval) {
            last if _get_shutdown_flag() || _get_reload_flag();
            sleep 1;
        }
    }

    $log->info("public_blocklist_thread ready to be joined");
    Log::Log4perl::MDC->remove("THREAD");

    return 1;
}

# -------------------------------------------------------------------------
# IP helper, static sets, and in-memory cache
# -------------------------------------------------------------------------

=head2 _is_never_block_ip

Description:
    Determine whether the given IP or CIDR should never be blocked,
    according to the configured never_block_cidrs.

Arguments:
    %args:
        ip   => string, IP or CIDR
        conf => hashref, configuration (must contain never_block_cidrs)

Returns:
    Boolean – 1 if IP should never be blocked, 0 otherwise.

=cut

sub _is_never_block_ip {
    my (%args) = @_;
    my $ip   = $args{ip};
    my $conf = $args{conf} || {};
    my $cidrs = $conf->{never_block_cidrs} || [];
    return 0 unless @$cidrs;
    return cidrlookup($ip, @$cidrs) ? 1 : 0;
}

=head2 _refresh_static_nftables_sets

Description:
    Refresh the static nftables sets "never_block" and "always_block"
    from configuration.

Arguments:
    (method) $self – object instance.

Returns:
    Nothing.

=cut

sub _refresh_static_nftables_sets {
    my ($self) = @_;

    my $table        = $self->{conf}->{nft_table};
    my $family_table = $self->{conf}->{nft_family_table};

    # never_block
    $log->info("Refreshing never_block nftables set");
    my $never_cidrs = $self->{conf}->{never_block_cidrs} || [];

    system("nft flush set $table $family_table never_block 2>/dev/null");

    for my $cidr (@$never_cidrs) {
        next unless $cidr;
        $cidr =~ s/^\s+|\s+$//g;
        next unless $cidr;
        my $rc = system("nft add element $table $family_table never_block { $cidr } 2>/dev/null");
        if ($rc == 0) {
            $log->debug("Added $cidr to never_block set");
        } else {
            $log->info("Failed to add $cidr to never_block set");
        }
    }

    # always_block
    $log->info("Refreshing always_block nftables set");
    my $always_cidrs = $self->{conf}->{always_block_cidrs} || [];
    system("nft flush set $table $family_table always_block 2>/dev/null");

    for my $cidr (@$always_cidrs) {
        next unless $cidr;
        $cidr =~ s/^\s+|\s+$//g;
        next unless $cidr;
        my $rc = system("nft add element $table $family_table always_block { $cidr } 2>/dev/null");
        if ($rc == 0) {
            $log->debug("Added $cidr to always_block set");
        } else {
            $log->info("Failed to add $cidr to always_block set");
        }
    }

    $log->info("Static sets refreshed: "
        . scalar(@$never_cidrs) . " never_block, "
        . scalar(@$always_cidrs) . " always_block");
}

=head2 _initial_load_blocked_ips

Description:
    On startup, read the nftables ruleset in JSON and populate the
    in-memory blocked hash with IPs and their expiry times.

Arguments:
    (method) $self – object instance.

Returns:
    Nothing.

=cut

sub _initial_load_blocked_ips {
    my ($self) = @_;
    $self->{blocked} = {};
    my $json = $self->_nft_as_json();

    for my $item (@{$json->{nftables} || []}) {
        next unless $item->{set}
            && $item->{set}->{name}
            && $item->{set}->{name} eq $self->{conf}->{nft_set};

        for my $elem (@{$item->{set}->{elem} || []}) {
            my $ip      = $elem->{elem}->{val};
            my $expires = $elem->{elem}->{expires} + time();
            $self->{blocked}{$ip} = $expires;
        }
    }

    $log->info("Loaded " . scalar(keys %{$self->{blocked}}) . " IP(s) from existing nftables set");
}

=head2 _nft_as_json

Description:
    Run "nft -j list ruleset" and decode the JSON output.

Arguments:
    (method) $self – object instance (not used).

Returns:
    Hashref decoded from JSON output.

=cut

sub _nft_as_json {
    my ($self) = @_;
    my $out = `nft -j list ruleset`;
    return decode_json($out);
}

=head2 _remove_expired_ips

Description:
    Remove IPs from the in-memory blocked cache whose expiry time has
    passed. This does NOT modify nftables itself, only the in-memory
    view.

Arguments:
    (method) $self – object instance.

Returns:
    Nothing.

=cut

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

=head2 _reload_blocked_ips

Description:
    Clear and repopulate the in-memory blocked IP cache from nftables.

Arguments:
    (method) $self – object instance.

Returns:
    Nothing.

=cut

sub _reload_blocked_ips {
    my ($self) = @_;
    $self->{blocked} = {};
    $self->_initial_load_blocked_ips();
}

# -------------------------------------------------------------------------
# Queue draining + heartbeat
# -------------------------------------------------------------------------

=head2 _drain_queues

Description:
    On shutdown, signal all queues to end and wait up to the configured
    graceful_shutdown_timeout for them to drain, logging any remaining
    items.

Arguments:
    (method) $self – object instance.

Returns:
    Nothing.

=cut

sub _drain_queues {
    my ($self) = @_;
    my $timeout = $self->{conf}->{graceful_shutdown_timeout} || 20;

    # First, get the pending counts for each queue
    my $pending_ips       = $ips_to_block_queue       ? $ips_to_block_queue->pending()       : 0;
    my $pending_db_sync   = $sync_to_central_db_queue ? $sync_to_central_db_queue->pending() : 0;

    # End queues so threads can stop blocking on dequeue
    $ips_to_block_queue->end()       if $ips_to_block_queue;
    $sync_to_central_db_queue->end() if $sync_to_central_db_queue;

    # Wait for queues to drain
    $log->info("Waiting for ips_to_block_queue to drain (up to $timeout seconds). Pending: $pending_ips");
    # $log->info("Waiting for ips_to_block_queue to drain (up to $timeout seconds).");
    my $max_wait = time() + $timeout;
    while ($ips_to_block_queue && $ips_to_block_queue->pending() && time() < $max_wait) {
        sleep 1;
        $log->info("ips_to_block_queue pending: " . $ips_to_block_queue->pending());
        $log->info("Will bypass ips_to_block_queue in " 
            . ($max_wait - time()) . " second" . (($max_wait - time()) == 1 ? "" : "s") . " if needed");
    }
    if ($ips_to_block_queue && $ips_to_block_queue->pending()) {
        $log->warn("Timeout reached for ips_to_block_queue, pending: " . $ips_to_block_queue->pending());
    }

    $log->info("Waiting for sync_to_central_db_queue to drain (up to $timeout seconds). Pending: $pending_db_sync");
    $max_wait = time() + $timeout;
    while ($sync_to_central_db_queue && $sync_to_central_db_queue->pending() && time() < $max_wait) {
        sleep 1;
        $log->info("sync_to_central_db_queue pending: " . $sync_to_central_db_queue->pending());
        $log->info("Will bypass sync_to_central_db_queue in " 
                    . ($max_wait - time()) . " second" . (($max_wait - time()) == 1 ? "" : "s") . " if needed");
    }
    if ($sync_to_central_db_queue && $sync_to_central_db_queue->pending()) {
        $log->warn("Timeout reached for sync_to_central_db_queue, pending: " . $sync_to_central_db_queue->pending());
        # Now drain the queue to avoid errors on program exit
        while (my $item = $sync_to_central_db_queue->dequeue_nb()) {
            $log->debug("Draining sync_to_central_db_queue item: " . Dumper($item));
        }
    }

    # Optional: debug-drain remaining items
    if ($ips_to_block_queue) {
        while (my $item = $ips_to_block_queue->dequeue_nb()) {
            $log->debug("Draining ips_to_block_queue item: " . Dumper($item));
        }
    }
    if ($sync_to_central_db_queue) {
        while (my $item = $sync_to_central_db_queue->dequeue_nb()) {
            $log->debug("Draining sync_to_central_db_queue item: " . Dumper($item));
        }
    }
}

=head2 heartbeat_info

Description:
    Emit a periodic heartbeat log message summarizing current state,
    including total blocked IPs, run count, and queue depths. Also logs
    newly blocked IPs since the previous heartbeat.

Arguments:
    (method) $self – object instance.
    %args:
        heartbeat_interval => integer seconds (for logging only)
        new_since_hb       => hashref of IP => 1

Returns:
    Nothing.

=cut

sub heartbeat_info {
    my ($self, %args) = @_;
    my $interval     = $args{heartbeat_interval} // 300;
    my $new_since_hb = $args{new_since_hb}       || {};
    my $next_hb_at   = $args{next_heartbeat_at}  || (time() + $interval);
    my %new          = %$new_since_hb;

    $self->_reload_blocked_ips();

    my @sorted = sort { $self->{blocked}{$a} <=> $self->{blocked}{$b} } keys %{$self->{blocked}};
    my @new_ips = sort { $a cmp $b } keys %new;

    $log->info("Heartbeat: Total blocked IPs: " . scalar(@sorted));
    $log->info("Run count: $self->{run_count}");
    my $q1 = $ips_to_block_queue       ? $ips_to_block_queue->pending()       : 0;
    my $q2 = $sync_to_central_db_queue ? $sync_to_central_db_queue->pending() : 0;
    my $dt = strftime("%Y-%m-%d %H:%M:%S", localtime($next_hb_at));
    $log->info("Queue depths: ips_to_block=$q1, sync_to_central_db=$q2.  Next heartbeat at $dt");

    if (@new_ips) {
        $log->info("Newly blocked since last heartbeat (" . scalar(@new_ips) . "): " . join(", ", @new_ips));
    } else {
        $log->info("No new IPs since last heartbeat");
    }
}

# -------------------------------------------------------------------------
# Log reading + pattern matching
# -------------------------------------------------------------------------

=head2 _read_all_sources

Description:
    Aggregate log entries from journald units and file sources.

Arguments:
    (method) $self – object instance.
    %args:
        max_file_lines      => integer, max lines per file to read from tail
        read_journal_since  => epoch seconds, earliest journal time to read

Returns:
    Hashref:
        {
          unit_or_file => {
              key => "msg1|msg2|...",
              ...
          },
          ...
        }

=cut

sub _read_all_sources {
    my ($self, %args) = @_;
    my $max                = $args{max_file_lines}      // 2000;
    my $read_journal_since = $args{read_journal_since}  // time() - ($self->{conf}->{sleep_time} // 60);

    my $entries = {};

    # Journald units
    my $units = $self->{conf}->{journal_units} || [];
    for my $unit (@$units) {
        $log->debug("Reading journal for unit $unit since epoch $read_journal_since");
        my $u = $self->_read_journal_unit($unit, $read_journal_since);
        $entries->{$unit} = $u;
    }

    # File sources
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

=head2 _read_files_recent

Description:
    Read up to max_lines recent lines from each configured log file, in
    reverse (tail) order, and keep only lines with IPv4 addresses.

Arguments:
    (method) $self – object instance.
    $files    => arrayref of file paths
    $max_lines=> integer, max lines per file

Returns:
    Hashref:
        {
          "file:/path" => {
              "file:/path:N" => "line|line|...",
              ...
          },
          ...
        }

=cut

sub _read_files_recent {
    my ($self, $files, $max_lines) = @_;
    my %by_unit;

    FILE:
    for my $path (@$files) {
        next FILE unless defined $path && -r $path;

        my $unit_key = "file:$path";
        my $count    = 0;

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
                $by_unit{$unit_key}{$pidish} = $line;
            }
        }
    }

    return \%by_unit;
}

=head2 _get_journal_lines

Description:
    Run journalctl for a given unit and time range, returning only JSON
    entries that contain IPv4 or IPv6 addresses in the MESSAGE field.

Arguments:
    (method) $self – object instance.
    %args:
        unit        => string, journald unit name
        since_epoch => integer, earliest time
        until_epoch => integer, latest time

Returns:
    Arrayref of hashrefs:
        [ { MESSAGE => "...", ... }, ... ]

=cut

sub _get_journal_lines {
    my ($self, %args) = @_;
    my $unit        = $args{unit}        || '';
    my $since_epoch = $args{since_epoch} || time();
    my $until_epoch = $args{until_epoch} || time();

    my @lines;
    my $cmd = "journalctl --unit=$unit --since=\@$since_epoch --until=\@$until_epoch --no-pager -o json";

    open(my $fh, "-|", $cmd) or do {
        $log->warn("Failed to open journalctl for unit $unit: $!");
        return \@lines;
    };

    while (my $line = <$fh>) {
        chomp $line;
        next unless $line =~ /\S/;

        my $entry = eval { decode_json($line) };
        if ($@) {
            $log->warn("Failed to parse journalctl JSON line: $@");
            next;
        }

        my $msg = $entry->{MESSAGE} // '';
        next unless ( $self->has_ipv4($msg) || $self->has_ipv6($msg) );

        push @lines, { MESSAGE => $msg };
    }

    close($fh);
    return \@lines;
}

=head2 _read_journal_unit

Description:
    Read journal entries for a single unit since a given epoch, and
    return a hashref keyed by synthetic "threadid" with pipes joining
    multiple lines.

Arguments:
    (method) $self – object instance.
    $unit             => string, journald unit name
    $read_journal_since => integer, earliest epoch

Returns:
    Hashref of:
        {
          "unit:counter" => "msg|msg|...",
          ...
        }

=cut

sub _read_journal_unit {
    my ($self, $unit, $read_journal_since) = @_;
    $read_journal_since = int($read_journal_since);

    my $entries = {};

    my $lines = $self->_get_journal_lines(
        unit        => $unit,
        since_epoch => $read_journal_since,
        until_epoch => time(),
    );

    my @lines_arr = @$lines;
    my %lines_hash;
    my $counter = 1;

    for my $line (@lines_arr) {
        my $msg = $line->{MESSAGE} || '';
        $lines_hash{$msg} = $counter++;
    }

    for my $msg (keys %lines_hash) {
        my $threadid = "$unit:" . ($lines_hash{$msg} || 'unknown');
        $entries->{$threadid} = defined $entries->{$threadid}
            ? "$entries->{$threadid}|$msg"
            : $msg;
    }

    return $entries;
}

=head2 has_ipv4

Description:
    Return true if the provided string contains an IPv4 address.

Arguments:
    (method) $self – object instance (unused).
    $string        => string to inspect.

Returns:
    Boolean – 1 if IPv4 found, 0 otherwise.

=cut

sub has_ipv4 {
    my ($self, $string) = @_;
    return ($string =~ /$RE{net}{IPv4}/) ? 1 : 0;
}

=head2 has_ipv6

Description:
    Return true if the provided string contains an IPv6 address.

Arguments:
    (method) $self – object instance (unused).
    $string        => string to inspect.

Returns:
    Boolean – 1 if IPv6 found, 0 otherwise.

=cut

sub has_ipv6 {
    my ($self, $string) = @_;
    return ($string =~ /$RE{net}{IPv6}/) ? 1 : 0;
}

=head2 _bad_entries

Description:
    Filter log entries against compiled bad connection patterns and
    return a hashref of "bad" entries with metadata.

Arguments:
    (method) $self – object instance.
    $entries        => hashref from _read_all_sources().

Returns:
    Hashref:
        {
          key => {
            msg         => "...",
            unit        => "...",
            pattern_num => integer,
            pattern     => original pattern,
            detector    => "name",
            service     => "name",
          },
          ...
        }

=cut

sub _bad_entries {
    my ($self, $entries) = @_;
    my %bad;

    my $patterns = $self->{conf}->{compiled_patterns}
        ? $self->{conf}->{compiled_patterns}
        : [ map { qr/$_/ } @{$self->{conf}->{bad_conn_patterns} || []} ];

    my $total_entries = 0;
    for my $unit (keys %$entries) {
        $total_entries += scalar(keys %{$entries->{$unit}});
    }
    $log->debug("Checking $total_entries log entries against " . scalar(@$patterns) . " patterns");

    for my $unit (keys %$entries) {
        my $u = $entries->{$unit};
        ENTRY: for my $pid (keys %$u) {
            my $msg = $u->{$pid};
            my $pattern_num = 0;
            for my $re (@$patterns) {
                $pattern_num++;
                if ($msg =~ $re) {
                    my $pattern = $self->{conf}->{bad_conn_patterns}->[$pattern_num - 1] || 'unknown';
                    $bad{$pid} = {
                        msg         => $msg,
                        unit        => $unit,
                        pattern_num => $pattern_num,
                        pattern     => $pattern,
                        detector    => $self->_detector_name_from_unit($unit),
                        service     => $self->_service_name_from_unit($unit),
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

=head2 _detector_name_from_unit

Description:
    Derive a detector name from a log unit string, e.g. sshd.service ->
    sshd; file:/path -> file.

Arguments:
    (method) $self – object instance.
    $unit          => string

Returns:
    String detector name.

=cut

sub _detector_name_from_unit {
    my ($self, $unit) = @_;
    return 'file' if $unit =~ /^file:/;
    my ($name) = $unit =~ /^([^\.]+)/;
    return $name || 'unknown';
}

=head2 _service_name_from_unit

Description:
    Derive a service name from a log unit string, same behavior as
    _detector_name_from_unit for now.

Arguments:
    (method) $self – object instance.
    $unit          => string.

Returns:
    String service name.

=cut

sub _service_name_from_unit {
    my ($self, $unit) = @_;
    return 'file' if $unit =~ /^file:/;
    my ($name) = $unit =~ /^([^\.]+)/;
    return $name || 'unknown';
}

=head2 _remote_addresses

Description:
    Extract IP addresses from bad entries, build metadata, and return an
    arrayref of items suitable for enqueuing to ips_to_block_queue.

Arguments:
    (method) $self – object instance.
    $entries        => hashref from _bad_entries().

Returns:
    Arrayref:
        [
          {
            ip       => 'x.x.x.x',
            metadata => {
                service  => 'ssh',
                detector => 'sshd',
                pattern  => 'patternN: ...',
                log_line => 'original log line',
            },
          },
          ...
        ]

=cut

sub _remote_addresses {
    my ($self, $entries) = @_;
    my %ip_metadata;

    $log->debug("Extracting IPs from " . scalar(keys %$entries) . " bad entries");
    $log->debug("Bad entries detail:\n" . Dumper($entries));

    for my $k (keys %$entries) {
        my $entry = $entries->{$k};
        my $msg   = ref($entry) eq 'HASH' ? $entry->{msg} : $entry;

        my @found_ips;
        while ($msg =~ /$RE{net}{IPv4}/g) {
            push @found_ips, $&;
        }

        $log->debug("Extracted " . scalar(@found_ips) . " IPs from log entry") if @found_ips;

        if (@found_ips && ref($entry) eq 'HASH') {
            for my $ip (@found_ips) {
                next if exists $ip_metadata{$ip};
                $ip_metadata{$ip} = {
                    service  => $entry->{service},
                    detector => $entry->{detector},
                    pattern  => "pattern$entry->{pattern_num}: $entry->{pattern}",
                    log_line => $entry->{msg},
                };
                $log->debug("Found IP $ip from detector '$entry->{detector}'");
            }
        } elsif (@found_ips) {
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

    return [ map { { ip => $_, metadata => $ip_metadata{$_} } } @ips ];
}

1;


