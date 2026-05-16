package BadIPs::Plugins::GeneralLogMonitor;

use strict;
use warnings;
use File::Slurp qw(read_file);
use Log::Log4perl qw(get_logger);
use Regexp::Common qw(net);  # Exports %RE{net}
use Data::Dumper;
use List::Util qw(any);
use JSON qw(decode_json);
our $VERSION = '3.5.4';

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

    my $plugin_confs = $self->{conf}->get_block( section => $self->{plugin_section} );
    $self->{monitor_method} = $plugin_confs->{monitor_method} || 'auto';
    $self->{units} = $plugin_confs->{units} || [];
    $self->{file_paths} = $plugin_confs->{log_paths} || [];
    $self->{initial_fetch} = $plugin_confs->{initial_fetch} || 300;
    $self->{fetch_interval} = $plugin_confs->{fetch_interval} || 60;
    $self->{file_positions} = {};

    # Extract the matching patterns for failed login attempts
    # Creates a hash like:
    # { 'short_description' => 'regex_pattern' }
    # Pushes into $self->{patterns}
    # Expects config entries like:
    #  bad_login_pattern_01 = Failed password:::Failed password for .* from
    #  Splits on ::: to get description and pattern
    my %patterns;
    for my $key (keys %$plugin_confs) {
        if ($key =~ /^bad_login_pattern_\d+$/) {
            my $value = $plugin_confs->{$key};
            my ($desc, $pattern) = split(/:::/, $value, 2);
            if (defined $desc && defined $pattern) {
                $patterns{$desc} = $pattern;
            } else {
                $log->warn("Invalid bad_login_pattern entry '$value' in plugin section '$self->{plugin_section}'");
            }
        }
    }
    $self->{patterns} = \%patterns;

    my %files_to_monitor = map { $_ => 1 } @{ $self->{log_paths} };
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

    # While there is no shutdown signal or reload signal, continue monitoring
    while (1) {
        # Sleep for a configured interval before next check
        my $next_check = time() + $self->{fetch_interval};
        while (time() < $next_check) {
            if ( $self->shutdown_check() ) {
                $self->{log}->info("Shutdown signal received during sleep; exiting log monitoring");
                last;
            }
            if ( $self->reload_check() ) {
                $self->{log}->info("Reload signal received during sleep; exiting log monitoring for reload");
                last;
            }
            sleep(1);
        }
        # Fetch new log lines since last check
        my $lines = [];
        $lines = $self->_recurring_fetch_lines();
        $self->{log}->info("Fetched " . scalar(@$lines) . " new relevant log lines");
        # Enqueue IPs found in new log lines
        $self->_add_ips_to_queue( lines => $lines );
    }


    $self->{log}->info("Log monitoring completed");

    return 1;
}

=head2 _add_ips_to_queue
Description:
    Helper sub to enqueue IPs found in log lines.
Arguments:
    lines => arrayref of hashrefs:
        [ { message => "...", description => "..." }, ... ]
Returns:
    None.
=cut
sub _add_ips_to_queue {
    my ($self, %args) = @_;
    my $lines = $args{lines} || [];

    # get unique IPs from lines
    my %unique_ips;
    for my $line (@$lines) {
        my $message = $line->{message} || '';
        while ( $message =~ /($RE{net}{IPv4}|$RE{net}{IPv6})/g ) {
            $unique_ips{$1} = 1;
        }
    }
    for my $ip (keys %unique_ips) {
        $self->{log}->info("Enqueuing IP $ip found in logs");
        $self->enqueue_ip( ip => $ip, reason => 'Failed login attempts' );
    }
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
    my $file_paths = $args{file_paths} || $self->{log_paths} || [];
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
    my @units = $args{units} || [];
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
    for my $pattern (keys %{ $self->{patterns} }) {
        if ( $message =~ /$self->{patterns}->{$pattern}/ ) {
            my $desc = $pattern;
            return { message => $message, description => $desc };
        }
    }
    return undef;
}

1;
