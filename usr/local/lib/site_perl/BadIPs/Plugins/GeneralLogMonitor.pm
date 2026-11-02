package BadIPs::Plugins::GeneralLogMonitor;

use strict;
use warnings;
use File::Slurp qw(read_file);
use Log::Log4perl qw(get_logger);
use Regexp::Common qw(net);  # Exports %RE{net}
use Data::Dumper;
use List::Util qw(any);
use JSON qw(decode_json);
our $VERSION = '3.8.0';

my $log = get_logger();

=head1 NAME

BadIPs::Plugins::GeneralLogMonitor - General plugin to monitor logs or journald for failed attempts

Plugin can monitor files, journald, both, or auto-detect based on configuration

=cut

sub new {
    my ($class, %args) = @_;

    my $self = {
        conf           => $args{conf},
        dry_run        => $args{dry_run} || 0,
        log            => $args{log} || get_logger(__PACKAGE__),
        reload_check   => $args{reload_check},
        shutdown_check => $args{shutdown_check},
        enqueue_ip     => $args{enqueue_ip},
        plugin_section => $args{plugin_section} || '',
    };

    # Extract plugin configuration from nested hash
    # plugin_section is "Plugins:GeneralLogMonitor"
    my $plugin_confs = {};
    if ($self->{plugin_section} && $self->{plugin_section} =~ /^Plugins:(.+)$/) {
        my $plugin_name = $1;
        $plugin_confs = $self->{conf}->{Plugins}->{$plugin_name} || {};
    }
    $self->{monitor_method} = $plugin_confs->{monitor_method} || 'auto';

    # Parse journal units (comma-separated list)
    my $units = $plugin_confs->{journal_unit} || '';
    $self->{units} = $units ? [ split(/\s*,\s*/, $units) ] : [];

    # Parse file paths (comma-separated list)
    my $log_paths = $plugin_confs->{log_paths} || '';
    $self->{file_paths} = $log_paths ? [ split(/\s*,\s*/, $log_paths) ] : [];

    $self->{initial_fetch} = $plugin_confs->{initial_fetch} || 300;
    $self->{fetch_interval} = $plugin_confs->{fetch_interval} || 60;
    $self->{file_positions} = {};

    # Extract the detection patterns. Two kinds are recognised, each stored
    # as { 'short_description' => 'regex_pattern' }:
    #   bad_login_pattern_NN  -> $self->{patterns}       (evidence of attack)
    #   good_login_pattern_NN -> $self->{good_patterns}  (evidence a real
    #                                                     user authenticated)
    # Expects config entries like:
    #  bad_login_pattern_01  = Failed password:::Failed password for .* from
    #  good_login_pattern_01 = Accepted publickey:::Accepted publickey for .* from
    #  Splits on ::: to get description and pattern
    my %patterns;
    my %good_patterns;
    for my $key (keys %$plugin_confs) {
        my $target;
        if    ($key =~ /^bad_login_pattern_\d+$/)  { $target = \%patterns }
        elsif ($key =~ /^good_login_pattern_\d+$/) { $target = \%good_patterns }
        else                                       { next }

        my $value = $plugin_confs->{$key};
        my ($desc, $pattern) = split(/:::/, $value, 2);
        if (defined $desc && defined $pattern) {
            $target->{$desc} = $pattern;
        } else {
            $log->warn("Invalid $key entry '$value' in plugin section '$self->{plugin_section}'");
        }
    }
    $self->{patterns}      = \%patterns;
    $self->{good_patterns} = \%good_patterns;

    # How long a successful login protects an address from being blocked.
    # Without this the daemon had no notion of a legitimate user at all: a
    # key-based login followed seconds later by a harmless pre-auth disconnect
    # was enough to lock the real user out.
    $self->{good_login_grace} = $plugin_confs->{good_login_grace};
    $self->{good_login_grace} = 3600 unless defined $self->{good_login_grace} && $self->{good_login_grace} =~ /^\d+$/;

    # block_after_n_attempts was previously documented and shipped in the
    # config but never read by any code, so every single match blocked
    # immediately. It is now honoured, counted per address over
    # attempt_window seconds.
    $self->{block_after_n_attempts} = $plugin_confs->{block_after_n_attempts};
    $self->{block_after_n_attempts} = 1
        unless defined $self->{block_after_n_attempts}
            && $self->{block_after_n_attempts} =~ /^\d+$/
            && $self->{block_after_n_attempts} >= 1;

    $self->{attempt_window} = $plugin_confs->{attempt_window};
    $self->{attempt_window} = 600 unless defined $self->{attempt_window} && $self->{attempt_window} =~ /^\d+$/;

    # Per-address state: last successful login, and failure tallies.
    $self->{good_ips} = {};
    $self->{attempts} = {};

    my %files_to_monitor = map { $_ => 1 } @{ $self->{file_paths} };
    $self->{files_to_monitor} = \%files_to_monitor;

    bless $self, $class;
    return $self;
}

sub reload_check {
    my ($self) = @_;
    my $cb = $self->{reload_check} or return 0;
    return $cb->();
}

sub shutdown_check {
    my ($self) = @_;
    my $cb = $self->{shutdown_check} or return 0;
    return $cb->();
}

sub enqueue_ip {
    my ($self, %args) = @_;
    my $cb = $self->{enqueue_ip} or return;
    return $cb->(%args);
}

sub run {
    my ($self) = @_;

    $self->{log}->info("Starting log monitoring for failed login attempts");

    # Initial fetch of log lines
    my $lines = [];
    $lines = $self->_initial_fetch_lines();
    $self->{log}->info("Initial fetch found " . scalar(@$lines) . " relevant log lines");

    # Process IPs from initial historical lines
    $self->_add_ips_to_queue( lines => $lines );

    # While there is no shutdown signal or reload signal, continue monitoring
    while (1) {
        # Sleep for a configured interval before next check
        my $next_check = time() + $self->{fetch_interval};
        while (time() < $next_check) {
            # return (not last): "last" only left this sleep loop, so the
            # outer loop kept polling the logs until the thread was killed
            # and, on reload, kept running alongside the new plugin thread.
            if ( $self->shutdown_check() ) {
                $self->{log}->info("Shutdown signal received during sleep; exiting log monitoring");
                return 1;
            }
            if ( $self->reload_check() ) {
                $self->{log}->info("Reload signal received during sleep; exiting log monitoring for reload");
                return 1;
            }
            sleep(1);
        }
        # Fetch new log lines since last check
        my $lines = [];
        $lines = $self->_recurring_fetch_lines();
        my $count = scalar(@$lines);
        if ($count > 0) {
            $self->{log}->info("Fetched $count new relevant log lines");
        } else {
            $self->{log}->debug("Fetched 0 new relevant log lines");
        }
        # Enqueue IPs found in new log lines
        $self->_add_ips_to_queue( lines => $lines );
        $self->_prune_state();
    }
}

=head2 _add_ips_to_queue
Description:
    Helper sub to enqueue IPs found in log lines.
Arguments:
    lines => arrayref of hashrefs:
        [ { message => "...", description => "...", kind => 'bad'|'good' }, ... ]
Returns:
    1.
=cut
sub _add_ips_to_queue {
    my ($self, %args) = @_;
    my $lines = $args{lines} || [];
    my $now   = time();
    my $grace = $self->{good_login_grace};
    my $need  = $self->{block_after_n_attempts};

    # Pass 1 - record successful logins before looking at any failure.
    # Order matters: a success and a failure can easily land in the same
    # batch, which is exactly what locked real users out before. Recording
    # successes first means the failure pass already knows the address is
    # trusted.
    for my $line (@$lines) {
        next unless ( $line->{kind} || 'bad' ) eq 'good';
        my $desc = $line->{description} || 'successful login';
        for my $ip ( $self->_extract_client_ips( $line->{message} || '' ) ) {
            $self->{good_ips}->{$ip} = $now;
            delete $self->{attempts}->{$ip};
            $self->{log}->info("Successful login from $ip ($desc); exempt from blocking for ${grace}s");
        }
    }

    # Pass 2 - failures.
    for my $line (@$lines) {
        next unless ( $line->{kind} || 'bad' ) eq 'bad';
        my $desc = $line->{description} || 'unknown pattern';

        for my $ip ( $self->_extract_client_ips( $line->{message} || '' ) ) {

            my $good_at = $self->{good_ips}->{$ip};
            if ( defined $good_at && ( $now - $good_at ) <= $grace ) {
                my $ago = $now - $good_at;
                $self->{log}->info(
                    "Not blocking $ip ($desc): successful login ${ago}s ago is inside the ${grace}s grace window"
                );
                next;
            }

            my $rec = $self->{attempts}->{$ip} ||= { count => 0, first => $now };
            if ( ( $now - $rec->{first} ) > $self->{attempt_window} ) {
                $rec->{count} = 0;
                $rec->{first} = $now;
            }
            $rec->{count}++;

            if ( $rec->{count} >= $need ) {
                $self->{log}->info("Enqueuing IP $ip after $rec->{count}/$need attempt(s) ($desc)");
                $self->enqueue_ip( ip => $ip, reason => "Failed login attempts: $desc" );
                delete $self->{attempts}->{$ip};
            }
            else {
                $self->{log}->info(
                    "IP $ip at $rec->{count}/$need attempt(s) within $self->{attempt_window}s ($desc); not blocking yet"
                );
            }
        }
    }

    return 1;
}

=head2 _recurring_fetch_lines

Description:
    Perform a fetch of log lines since the last check based on the configured monitoring method.

Arguments:
    (method) $self – object instance.
Returns:
    Arrayref of hashrefs:
        [ { MESSAGE => "...", ... }, ... ]
=cut
sub _recurring_fetch_lines {
    my ($self) = @_;
    my $lines = [];
    if ($self->{monitor_method} eq 'files') {
        $lines = $self->_read_log_files();
    } elsif ($self->{monitor_method} eq 'journald') {
        $lines = $self->_get_journal_lines(
            since_epoch => time() - $self->{fetch_interval},
            until_epoch => time(),
        );
    } elsif ($self->{monitor_method} eq 'both') {
        my $file_lines = $self->_read_log_files();
        my $journal_lines = $self->_get_journal_lines(
            since_epoch => time() - $self->{fetch_interval},
            until_epoch => time(),
        );
        $lines = [ @$file_lines, @$journal_lines ];
    } elsif ($self->{monitor_method} eq 'auto') {
        # This is just both with a guess of unit (if not set) and file paths (if not set)
        if (!@{ $self->{units} }) {
            $self->{units} = [];
        }
        if (!@{ $self->{file_paths} }) {
            $self->{file_paths} = [];
        }
        my $file_lines = $self->_read_log_files();
        my $journal_lines = $self->_get_journal_lines(
            since_epoch => time() - $self->{fetch_interval},
            until_epoch => time(),
        );
        $lines = [ @$file_lines, @$journal_lines ];
    } else {
        $self->{log}->error("Invalid monitor_method '$self->{monitor_method}' in configuration");
        return [];
    }
    return $lines;
}

=head2 _initial_fetch_lines

Description:
    Perform an initial fetch of log lines based on the configured monitoring method.

Arguments:
    (method) $self – object instance.

Returns:
    Arrayref of hashrefs:
        [ { MESSAGE => "...", ... }, ... ]
=cut
sub _initial_fetch_lines {
    my ($self) = @_;
    my $lines = [];
    if ($self->{monitor_method} eq 'files') {
        $lines = $self->_read_log_files();
    } elsif ($self->{monitor_method} eq 'journald') {
        $lines = $self->_get_journal_lines(
            since_epoch => time() - $self->{initial_fetch},
            until_epoch => time(),
        );
    } elsif ($self->{monitor_method} eq 'both') {
        my $file_lines = $self->_read_log_files();
        my $journal_lines = $self->_get_journal_lines(
            since_epoch => time() - $self->{initial_fetch},
            until_epoch => time(),
        );
        $lines = [ @$file_lines, @$journal_lines ];
    } elsif ($self->{monitor_method} eq 'auto') {
        # This is just both with a guess of unit (if not set) and file paths (if not set)
        if (!@{ $self->{units} }) {
            $self->{units} = [];
        }
        if (!@{ $self->{file_paths} }) {
            $self->{file_paths} = [];
        }
        my $file_lines = $self->_read_log_files();
        my $journal_lines = $self->_get_journal_lines(
            since_epoch => time() - $self->{initial_fetch},
            until_epoch => time(),
        );
        $lines = [ @$file_lines, @$journal_lines ];
    } else {
        $self->{log}->error("Invalid monitor_method '$self->{monitor_method}' in configuration");
        return [];
    }
    return $lines;
}


=head2 _read_log_files

Description:
    Read specified log files and return lines containing IPv4 or IPv6 addresses and matching patterns.
    Reads log files from last known positions to end of files.

Arguments:
    (method) $self – object instance.

Returns:
    Arrayref of hashrefs:
        [ { MESSAGE => "...", ... }, ... ]
=cut
sub _read_log_files {
    my ($self, %args) = @_;
    my $file_paths = $args{file_paths} || $self->{file_paths} || [];
    my @all_lines = ();

    for my $file_path (@$file_paths) {
        my $lines = $self->_read_log_file( file_path => $file_path );
        push @all_lines, @$lines;
    }

    return \@all_lines;
}

=head2 _read_log_file

Description:
    Read a log file and return lines containing IPv4 or IPv6 addresses and matching patterns.

    Reads log file from last known position to end of file.
    If file is shorter than last known position, reads from start of file.

Arguments:
    (method) $self – object instance.
    %args:
        file_path => string, path to the log file.

Returns:
    Arrayref of hashrefs:
        [ { MESSAGE => "...", ... }, ... ]
=cut
sub _read_log_file {
    my ($self, %args) = @_;
    my $file_path = $args{file_path} || '';
    return [] unless $file_path && -e $file_path;

    my $last_position = $self->{file_positions}->{$file_path} || 0;
    my $file_size = -s $file_path;
    my $start_position = ($file_size < $last_position) ? 0 : $last_position;
    my @lines = ();
    open(my $fh, '<', $file_path) or do {
        $log->warn("Failed to open log file $file_path: $!");
        return [];
    };
    seek($fh, $start_position, 0);
    while (my $line = <$fh>) {
        chomp $line;
        next unless $line =~ /\S/;
        next unless ( $self->has_ipv4($line) || $self->has_ipv6($line) );
        my $match = $self->_matchs_patterns($line);
        next unless $match;
        push @lines, $match;
    }
    $self->{file_positions}->{$file_path} = tell($fh);
    close($fh);
    return \@lines;
}

=head2 _get_journal_lines

Description:
    Run journalctl for a given unit and time range, returning only JSON
    entries that contain IPv4 or IPv6 addresses in the MESSAGE field and
    match any of the defined patterns.

Arguments:
    (method) $self – object instance.
    %args:
        units         => arrayref of strings, journald unit names
        since_epoch  => integer, earliest time
        until_epoch  => integer, latest time

Returns:
    Arrayref of hashrefs:
        [ { MESSAGE => "...", ... }, ... ]
=cut
sub _get_journal_lines {
    my ($self, %args) = @_;
    my @units = @{ $args{units} || $self->{units} || [] };
    my $since_epoch = $args{since_epoch} || time();
    my $until_epoch = $args{until_epoch} || time();

    my @all_entries = ();
    for my $unit (@units) {
        my $entries = $self->_get_journal_lines_for_unit(
            unit        => $unit,
            since_epoch => $since_epoch,
            until_epoch => $until_epoch,
        );
        push @all_entries, @$entries;
    }

    return \@all_entries;
}

=head2 _get_journal_lines_for_unit

Description:
    Run journalctl for a given unit and time range, returning only JSON
    entries that contain IPv4 or IPv6 addresses in the MESSAGE field and
    match any of the defined patterns.

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

sub _get_journal_lines_for_unit {
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
        my $match = $self->_matchs_patterns($msg);
        next unless $match;

        push @lines, $match;
    }

    close($fh);
    return \@lines;
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

=head2 _matchs_patterns

Description:
    Helper sub for checking if a log message matches any of the defined patterns.

Arguments:
    (method) $self – object instance.
    $message       => string log message to check.

Returns:
    { message => string log message to check, description => matching pattern description } if a match is found, undef otherwise.

=cut

sub _matchs_patterns {
    my ($self, $message) = @_;

    # Successful-login patterns are checked first and win outright. A line
    # proving a real user got in must never be counted as an attack, whatever
    # order the hash keys happen to come back in.
    for my $desc (keys %{ $self->{good_patterns} }) {
        if ( $message =~ /$self->{good_patterns}->{$desc}/ ) {
            return { message => $message, description => $desc, kind => 'good' };
        }
    }

    for my $desc (keys %{ $self->{patterns} }) {
        if ( $message =~ /$self->{patterns}->{$desc}/ ) {
            return { message => $message, description => $desc, kind => 'bad' };
        }
    }

    return undef;
}

=head2 _extract_client_ips

Description:
    Return the client address a log line is actually about.

    This used to harvest every address appearing anywhere in a matching line
    via a global match, which meant any line naming more than one host (a
    relay plus its client, a local interface address in a Postfix connect
    line, a forwarded-for chain) got all of them blocked, including innocent
    bystanders.

    Addresses are now located by their position relative to a known anchor
    word, most specific anchor first, and only the first match is returned.
    When no anchor is recognised we fall back to the first address in the
    line rather than all of them.

Arguments:
    (method) $self – object instance.
    $message       => string log message.

Returns:
    List of client IP addresses - normally exactly one, empty if none found.

=cut

sub _extract_client_ips {
    my ($self, $message) = @_;
    return () unless defined $message && length $message;

    my $ip = qr/(?:$RE{net}{IPv4}|$RE{net}{IPv6})/;

    # Ordered most specific first; each alternative must capture the client.
    my @anchors = (
        qr/rhost=($ip)/,                                                       # PAM
        qr/\brip=($ip)/,                                                       # Dovecot
        qr/\bclient:\s*($ip)/,                                                 # nginx
        qr/\b(?:closed|reset)\s+by\s+(?:authenticating\s+user\s+\S+\s+)?($ip)/, # sshd disconnects
        qr/\bfrom\s+(?:\S*?\[)?($ip)\]?/,                                      # sshd / postfix "from host[ip]"
        qr/\bwith\s+($ip)/,                                                    # sshd "Unable to negotiate with ip"
        qr/\bby\s+($ip)/,                                                      # generic "... by ip"
        qr/\[($ip)\]/,                                                         # bracketed, e.g. unknown[ip]
        qr/($ip)\s+port\s+\d+/,                                                # generic sshd shape
    );

    for my $anchor (@anchors) {
        return ($1) if $message =~ $anchor;
    }

    if ( $message =~ /($ip)/ ) {
        $self->{log}->debug("No client-IP anchor matched; using first address $1 in: $message");
        return ($1);
    }

    return ();
}

=head2 _prune_state

Description:
    Drop per-address bookkeeping that has aged out, so the success and
    failure tables cannot grow without bound on a busy host.

Arguments:
    (method) $self – object instance.

Returns:
    1.

=cut

sub _prune_state {
    my ($self) = @_;
    my $now = time();

    for my $ip ( keys %{ $self->{good_ips} } ) {
        delete $self->{good_ips}->{$ip}
            if ( $now - $self->{good_ips}->{$ip} ) > $self->{good_login_grace};
    }

    for my $ip ( keys %{ $self->{attempts} } ) {
        delete $self->{attempts}->{$ip}
            if ( $now - $self->{attempts}->{$ip}->{first} ) > $self->{attempt_window};
    }

    return 1;
}

1;
