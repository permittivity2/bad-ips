package BadIPs::Plugins::Postfix;

use strict;
use warnings;
use File::Slurp qw(read_file);
use Log::Log4perl qw(get_logger);
use Regexp::Common qw(net);  # Exports %RE{net}
use JSON qw(decode_json);
our $VERSION = '3.5.23';

my $log = get_logger();

=head1 NAME

BadIPs::Plugins::Postfix - Postfix-specific monitoring plugin for Bad IPs

Monitors Postfix logs for authentication failures and protocol violations.
Implements threshold-based detection for distributed brute force attacks
targeting specific usernames, plus immediate blocking for protocol violations.

=head1 ATTACK PATTERNS

The plugin detects and handles three main categories of attacks:

1. PROTOCOL_VIOLATIONS (immediate per-IP block)
   - Non-SMTP commands
   - Improper pipelining
   - Illegal syntax

2. SASL_FAILURES (username-based threshold)
   - Multiple failed authentication attempts to the same username
   - Escalating block durations based on repeat offenses
   - Blocks ALL IPs that attempted the username

3. RELAY_DENIALS (IP-based threshold)
   - Spam/relay attempts
   - Escalating blocks for persistent offenders

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
    my $plugin_confs = {};
    if ($self->{plugin_section} && $self->{plugin_section} =~ /^Plugins:(.+)$/) {
        my $plugin_name = $1;
        $plugin_confs = $self->{conf}->{Plugins}->{$plugin_name} || {};
    }

    # Journal monitoring settings
    my $units = $plugin_confs->{journal_unit} || 'postfix@-.service, postfix.service';
    $self->{units} = [ split(/\s*,\s*/, $units) ];
    $self->{initial_fetch} = $plugin_confs->{initial_fetch} || 300;
    $self->{fetch_interval} = $plugin_confs->{fetch_interval} || 5;

    # Threshold configuration
    $self->{thresholds} = {
        protocol_violations => {
            count  => $plugin_confs->{protocol_violations_count} || 1,
            window => $plugin_confs->{protocol_violations_window} || 1,
        },
        sasl_failures => {
            count  => $plugin_confs->{sasl_failures_count} || 3,
            window => $plugin_confs->{sasl_failures_window} || 600,
        },
        relay_denials => {
            count  => $plugin_confs->{relay_denials_count} || 2,
            window => $plugin_confs->{relay_denials_window} || 300,
        },
        ssl_errors => {
            count  => $plugin_confs->{ssl_errors_count} || 5,
            window => $plugin_confs->{ssl_errors_window} || 600,
        },
    };

    # Escalating block durations (TTL in seconds)
    $self->{escalation_ttls} = {
        1 => $plugin_confs->{escalation_ttl_1} || 600,      # 10 minutes
        2 => $plugin_confs->{escalation_ttl_2} || 3600,     # 1 hour
        3 => $plugin_confs->{escalation_ttl_3} || 21600,    # 6 hours
        4 => $plugin_confs->{escalation_ttl_4} || 86400,    # 24 hours
        5 => $plugin_confs->{escalation_ttl_5} || 604800,   # 7 days
    };

    $self->{cleanup_interval} = $plugin_confs->{cleanup_interval} || 300;

    # State tracking for username-based SASL attacks
    # $username => { attempts => [...], offense_count => N, last_triggered_at => ts, ... }
    $self->{username_tracking} = {};

    # State tracking for IP-based violations
    # $ip => { protocol_violations => [...], relay_denials => [...], offense_count => N, ... }
    $self->{ip_tracking} = {};

    # Track IPs already enqueued to avoid duplicates within same period
    $self->{already_blocked} = {};

    # Load patterns from config
    my %patterns_by_category;
    for my $key (keys %$plugin_confs) {
        if ($key =~ /^pattern_(\w+)_(\d+)$/) {
            my $category = $1;
            my $value    = $plugin_confs->{$key};
            my ($desc, $pattern) = split(/:::/, $value, 2);
            if (defined $desc && defined $pattern) {
                $patterns_by_category{$category} ||= {};
                $patterns_by_category{$category}{$desc} = $pattern;
            } else {
                $self->{log}->warn("Invalid pattern entry '$value' in plugin section '$self->{plugin_section}'");
            }
        }
    }
    $self->{patterns} = \%patterns_by_category;

    # Verify patterns are configured
    if (!%patterns_by_category) {
        $self->{log}->warn("No patterns configured for Postfix plugin; plugin will be inactive");
    }

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

=head2 run

Main plugin loop: fetches Postfix logs, analyzes patterns, tracks thresholds,
and enqueues IPs when thresholds are exceeded.

=cut

sub run {
    my ($self) = @_;

    $self->{log}->info("Starting Postfix plugin (threshold-based detection)");

    # Initial fetch of historical log lines
    my $lines = $self->_initial_fetch_lines();
    $self->{log}->info("Initial fetch found " . scalar(@$lines) . " relevant Postfix log lines");

    # Process initial lines
    $self->_process_log_lines($lines);

    my $last_cleanup = time();

    # Main monitoring loop
    while (1) {
        # Sleep for configured interval
        my $next_check = time() + $self->{fetch_interval};
        while (time() < $next_check) {
            if ($self->shutdown_check()) {
                $self->{log}->info("Shutdown signal received during sleep; exiting");
                return 1;
            }
            if ($self->reload_check()) {
                $self->{log}->info("Reload signal received during sleep; exiting for reload");
                return 1;
            }
            sleep(1);
        }

        # Fetch new log lines
        my $lines = $self->_recurring_fetch_lines();
        my $count = scalar(@$lines);
        if ($count > 0) {
            $self->{log}->info("Fetched $count new Postfix log lines");
            $self->_process_log_lines($lines);
        }

        # Periodic cleanup of old tracking data
        if (time() - $last_cleanup > $self->{cleanup_interval}) {
            $self->_cleanup_old_entries();
            $last_cleanup = time();
        }
    }

    return 1;
}

=head2 _initial_fetch_lines

Fetch initial set of historical log lines from journald.

=cut

sub _initial_fetch_lines {
    my ($self) = @_;
    return $self->_get_journal_lines(
        since_epoch => time() - $self->{initial_fetch},
        until_epoch => time(),
    );
}

=head2 _recurring_fetch_lines

Fetch new log lines since last check.

=cut

sub _recurring_fetch_lines {
    my ($self) = @_;
    return $self->_get_journal_lines(
        since_epoch => time() - $self->{fetch_interval},
        until_epoch => time(),
    );
}

=head2 _get_journal_lines

Fetch log entries from journald for Postfix units.

=cut

sub _get_journal_lines {
    my ($self, %args) = @_;
    my @units = @{ $self->{units} || [] };
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

Fetch log entries from journald for a specific unit.

=cut

sub _get_journal_lines_for_unit {
    my ($self, %args) = @_;
    my $unit        = $args{unit} || '';
    my $since_epoch = $args{since_epoch} || time();
    my $until_epoch = $args{until_epoch} || time();

    my @lines;
    my $cmd = "journalctl --unit=$unit --since=\@$since_epoch --until=\@$until_epoch --no-pager -o json";

    open(my $fh, "-|", $cmd) or do {
        $self->{log}->warn("Failed to open journalctl for unit $unit: $!");
        return \@lines;
    };

    while (my $line = <$fh>) {
        chomp $line;
        next unless $line =~ /\S/;

        my $entry = eval { decode_json($line) };
        if ($@) {
            $self->{log}->debug("Failed to parse journalctl JSON: $@");
            next;
        }

        my $msg = $entry->{MESSAGE} // '';
        next unless $msg;
        push @lines, { message => $msg };
    }

    close($fh);
    return \@lines;
}

=head2 _process_log_lines

Process an array of log lines and handle pattern matching and thresholds.

=cut

sub _process_log_lines {
    my ($self, $lines) = @_;
    return unless $lines && @$lines;

    for my $line_obj (@$lines) {
        my $line = $line_obj->{message} || '';
        next unless $line;

        # Try to match against each category of patterns
        my $result = $self->_match_patterns($line);
        next unless $result;

        my $category = $result->{category};
        my $pattern_desc = $result->{pattern_desc};

        if ($category eq 'protocol_violations') {
            # Immediate per-IP block
            my $ip = $self->_extract_ip($line);
            if ($ip) {
                $self->_handle_protocol_violation($ip, $pattern_desc, $line);
            }
        } elsif ($category eq 'sasl_failures') {
            # Username-based threshold tracking
            my $extracted = $self->_extract_sasl_info($line);
            if ($extracted && $extracted->{ip} && $extracted->{username}) {
                $self->_handle_sasl_failure($extracted->{ip}, $extracted->{username}, $line);
            }
        } elsif ($category eq 'relay_denials') {
            # IP-based threshold tracking
            my $ip = $self->_extract_ip($line);
            if ($ip) {
                $self->_handle_relay_denial($ip, $line);
            }
        } elsif ($category eq 'ssl_errors') {
            # SSL errors (can be ignored or tracked at low threshold)
            my $ip = $self->_extract_ip($line);
            if ($ip) {
                $self->_handle_ssl_error($ip, $line);
            }
        }
    }
}

=head2 _match_patterns

Test a log line against all patterns. Returns hashref with category and pattern description
if a match is found, undef otherwise.

=cut

sub _match_patterns {
    my ($self, $line) = @_;

    for my $category (keys %{ $self->{patterns} }) {
        my $patterns = $self->{patterns}{$category} || {};
        for my $desc (keys %$patterns) {
            my $pattern = $patterns->{$desc};
            if ($line =~ /$pattern/) {
                return { category => $category, pattern_desc => $desc };
            }
        }
    }
    return undef;
}

=head2 _extract_ip

Extract IP address from a Postfix log line.
Format: "from hostname[IP]:port" or similar

=cut

sub _extract_ip {
    my ($self, $line) = @_;

    # Postfix format: "from unknown[147.185.132.193]:52752"
    # or: "from ec2-13-58-162-150.us-east-2.compute.amazonaws.com[13.58.162.150]:60536"
    if ($line =~ /from (?:unknown|\S+)\[($RE{net}{IPv4}|$RE{net}{IPv6})\]/) {
        return $1;
    }

    # Fallback: just find any IP in the line
    if ($line =~ /($RE{net}{IPv4}|$RE{net}{IPv6})/) {
        return $1;
    }

    return undef;
}

=head2 _extract_sasl_info

Extract both IP and username from a SASL authentication failure line.
Format includes: sasl_username=user@domain

=cut

sub _extract_sasl_info {
    my ($self, $line) = @_;

    # Extract IP
    my $ip = $self->_extract_ip($line);
    return undef unless $ip;

    # Extract username
    my $username;
    if ($line =~ /sasl_username=(\S+?)(?:\s|$)/) {
        $username = $1;
    }

    return { ip => $ip, username => $username } if $username;
    return undef;
}

=head2 _handle_protocol_violation

Immediate per-IP blocking for protocol violations.

=cut

sub _handle_protocol_violation {
    my ($self, $ip, $pattern_desc, $line) = @_;

    # Get current block count for escalation
    my $tracking = $self->{ip_tracking}{$ip} || {};
    my $offense_count = $tracking->{offense_count} || 0;
    $offense_count++;
    $self->{ip_tracking}{$ip}{offense_count} = $offense_count;
    $self->{ip_tracking}{$ip}{last_blocked_at} = time();

    # Calculate escalating TTL
    my $ttl = $self->_calculate_escalating_ttl($offense_count);

    # Check if we should enqueue (avoid duplicate blocks within short period)
    if ($self->_should_enqueue_ip($ip)) {
        $self->{log}->info(sprintf(
            "Protocol violation from %s (offense #%d, TTL %ds): %s",
            $ip, $offense_count, $ttl, $pattern_desc
        ));

        $self->enqueue_ip(
            ip      => $ip,
            ttl     => $ttl,
            reason  => "Postfix protocol violation: $pattern_desc",
            pattern => $pattern_desc,
            line    => $line,
        );
    }
}

=head2 _handle_sasl_failure

Username-based threshold tracking for SASL authentication failures.
Blocks ALL IPs that attempted a username when threshold is exceeded.

=cut

sub _handle_sasl_failure {
    my ($self, $ip, $username, $line) = @_;

    my $now = time();

    # Initialize username tracking if needed
    if (!exists $self->{username_tracking}{$username}) {
        $self->{username_tracking}{$username} = {
            attempts           => [],
            offense_count      => 0,
            last_triggered_at  => 0,
            first_seen         => $now,
        };
    }

    my $tracking = $self->{username_tracking}{$username};

    # Add this attempt
    push @{ $tracking->{attempts} }, {
        ip        => $ip,
        timestamp => $now,
        blocked   => 0,
    };

    # Clean up attempts outside the time window
    my $window_start = $now - $self->{thresholds}{sasl_failures}{window};
    $tracking->{attempts} = [
        grep { $_->{timestamp} >= $window_start } @{ $tracking->{attempts} }
    ];

    # Check if threshold exceeded
    if (scalar(@{ $tracking->{attempts} }) >= $self->{thresholds}{sasl_failures}{count}) {
        $self->_trigger_sasl_blocking($username, $tracking, $line);
    }
}

=head2 _trigger_sasl_blocking

Trigger blocking when SASL threshold is exceeded for a username.
Blocks ALL IPs that attempted the username with escalating TTL.

=cut

sub _trigger_sasl_blocking {
    my ($self, $username, $tracking, $line) = @_;

    my $now = time();

    # Increment offense count for this username
    $tracking->{offense_count}++;
    $tracking->{last_triggered_at} = $now;

    # Calculate escalating TTL based on offense count
    my $ttl = $self->_calculate_escalating_ttl($tracking->{offense_count});

    # Get unique IPs that tried this username and haven't been blocked in this event
    my %unique_ips;
    for my $attempt (@{ $tracking->{attempts} }) {
        $unique_ips{ $attempt->{ip} } = 1 unless $attempt->{blocked};
    }
    my @ips_to_block = sort keys %unique_ips;

    $self->{log}->info(sprintf(
        "SASL threshold exceeded for username '%s' (offense #%d): %d IPs, TTL %ds",
        $username, $tracking->{offense_count}, scalar(@ips_to_block), $ttl
    ));

    # Enqueue all IPs with same escalating TTL
    for my $ip (@ips_to_block) {
        if ($self->_should_enqueue_ip($ip)) {
            # Mark as blocked in this event
            for my $attempt (@{ $tracking->{attempts} }) {
                $attempt->{blocked} = 1 if $attempt->{ip} eq $ip;
            }

            $self->enqueue_ip(
                ip              => $ip,
                ttl             => $ttl,
                reason          => "SASL auth failures targeting username: $username",
                pattern         => "SASL_FAILURE",
                line            => $line,
                target_username => $username,
            );
        }
    }
}

=head2 _handle_relay_denial

IP-based threshold tracking for relay access denials (spam attempts).

=cut

sub _handle_relay_denial {
    my ($self, $ip, $line) = @_;

    my $now = time();

    # Initialize IP tracking if needed
    if (!exists $self->{ip_tracking}{$ip}) {
        $self->{ip_tracking}{$ip} = {
            relay_denials     => [],
            offense_count     => 0,
            last_blocked_at   => 0,
        };
    }

    my $tracking = $self->{ip_tracking}{$ip};

    # Add this attempt
    push @{ $tracking->{relay_denials} }, {
        timestamp => $now,
    };

    # Clean up attempts outside the time window
    my $window_start = $now - $self->{thresholds}{relay_denials}{window};
    $tracking->{relay_denials} = [
        grep { $_->{timestamp} >= $window_start } @{ $tracking->{relay_denials} }
    ];

    # Check if threshold exceeded
    if (scalar(@{ $tracking->{relay_denials} }) >= $self->{thresholds}{relay_denials}{count}) {
        # Increment offense count and calculate TTL
        $tracking->{offense_count}++;
        $tracking->{last_blocked_at} = $now;
        my $ttl = $self->_calculate_escalating_ttl($tracking->{offense_count});

        if ($self->_should_enqueue_ip($ip)) {
            $self->{log}->info(sprintf(
                "Relay denial threshold exceeded for %s (offense #%d, TTL %ds)",
                $ip, $tracking->{offense_count}, $ttl
            ));

            $self->enqueue_ip(
                ip      => $ip,
                ttl     => $ttl,
                reason  => "Relay access denial attempts",
                pattern => "RELAY_DENIAL",
                line    => $line,
            );
        }
    }
}

=head2 _handle_ssl_error

Handle SSL errors - can be configured to block or just track.

=cut

sub _handle_ssl_error {
    my ($self, $ip, $line) = @_;

    # SSL errors are often from scanners (Censys, etc.)
    # By default we don't block them, but can track for analytics

    my $now = time();

    # Initialize IP tracking if needed
    if (!exists $self->{ip_tracking}{$ip}) {
        $self->{ip_tracking}{$ip} = {
            ssl_errors    => [],
            offense_count => 0,
        };
    }

    my $tracking = $self->{ip_tracking}{$ip};

    # Add this error
    push @{ $tracking->{ssl_errors} }, { timestamp => $now };

    # Clean up outside time window
    my $window_start = $now - $self->{thresholds}{ssl_errors}{window};
    $tracking->{ssl_errors} = [
        grep { $_->{timestamp} >= $window_start } @{ $tracking->{ssl_errors} }
    ];

    # Check if threshold exceeded (optional blocking for excessive SSL errors)
    # By default, this threshold is very high to avoid false positives
    # Uncomment below to enable blocking for SSL errors:
    # if (scalar(@{ $tracking->{ssl_errors} }) >= $self->{thresholds}{ssl_errors}{count}) {
    #     $tracking->{offense_count}++;
    #     my $ttl = $self->_calculate_escalating_ttl($tracking->{offense_count});
    #     if ($self->_should_enqueue_ip($ip)) {
    #         $self->enqueue_ip(
    #             ip      => $ip,
    #             ttl     => $ttl,
    #             reason  => "Excessive SSL errors",
    #             pattern => "SSL_ERROR",
    #             line    => $line,
    #         );
    #     }
    # }
}

=head2 _should_enqueue_ip

Check if an IP should be enqueued (avoid duplicate blocks within short period).

=cut

sub _should_enqueue_ip {
    my ($self, $ip) = @_;

    my $now = time();
    my $DUPLICATE_BLOCK_WINDOW = 600;  # 10 minutes

    # If IP was blocked recently, don't enqueue again
    if (exists $self->{already_blocked}{$ip}) {
        my $blocked_at = $self->{already_blocked}{$ip};
        if ($now - $blocked_at < $DUPLICATE_BLOCK_WINDOW) {
            return 0;
        }
    }

    # Mark IP as blocked now
    $self->{already_blocked}{$ip} = $now;
    return 1;
}

=head2 _calculate_escalating_ttl

Calculate the TTL for a given offense count.
Escalates from 10 minutes to 7 days for repeated offenses.

=cut

sub _calculate_escalating_ttl {
    my ($self, $offense_count) = @_;

    # Cap at offense level 5 (maximum escalation)
    my $level = $offense_count > 5 ? 5 : $offense_count;
    $level = 1 if $level < 1;

    my $ttl = $self->{escalation_ttls}{$level} || 600;
    return $ttl;
}

=head2 _cleanup_old_entries

Periodic cleanup of old tracking data.
- Removes completely unused entries (no activity in 1 hour)
- Resets offense_count for entries with 30 days of good behavior

=cut

sub _cleanup_old_entries {
    my ($self) = @_;

    my $now = time();
    my $max_age = 3600;           # 1 hour for complete removal
    my $reset_age = 30 * 86400;   # 30 days for offense_count reset

    my ($cleaned_usernames, $cleaned_ips, $reset_offenses) = (0, 0, 0);

    # Cleanup username tracking (SASL attacks)
    for my $username (keys %{ $self->{username_tracking} }) {
        my $data = $self->{username_tracking}{$username};

        # Reset offense_count if no recent attacks
        if ($data->{last_triggered_at} && $now - $data->{last_triggered_at} > $reset_age) {
            if ($data->{offense_count} > 0) {
                $self->{log}->debug(
                    "Resetting offense count for username '$username' (no attacks for 30 days)"
                );
                $data->{offense_count} = 0;
                $reset_offenses++;
            }
        }

        # Remove completely if no recent activity
        if ($data->{first_seen} && $now - $data->{first_seen} > $max_age) {
            my $has_recent = 0;
            for my $attempt (@{ $data->{attempts} || [] }) {
                if ($attempt->{timestamp} > ($now - $max_age)) {
                    $has_recent = 1;
                    last;
                }
            }
            unless ($has_recent) {
                delete $self->{username_tracking}{$username};
                $cleaned_usernames++;
            }
        }
    }

    # Cleanup IP tracking (protocol violations, relay denials, etc.)
    for my $ip (keys %{ $self->{ip_tracking} }) {
        my $data = $self->{ip_tracking}{$ip};

        # Reset offense_count if no recent violations
        if ($data->{last_blocked_at} && $now - $data->{last_blocked_at} > $reset_age) {
            if ($data->{offense_count} > 0) {
                $self->{log}->debug(
                    "Resetting offense count for IP $ip (good behavior for 30 days)"
                );
                $data->{offense_count} = 0;
                $reset_offenses++;
            }
        }

        # Remove completely if no recent activity (check all tracking arrays)
        my $has_recent = 0;
        for my $category (qw(protocol_violations relay_denials ssl_errors)) {
            my $list = $data->{$category} || [];
            for my $item (@$list) {
                if ($item->{timestamp} > ($now - $max_age)) {
                    $has_recent = 1;
                    last;
                }
            }
            last if $has_recent;
        }

        unless ($has_recent) {
            delete $self->{ip_tracking}{$ip};
            $cleaned_ips++;
        }
    }

    # Cleanup the "already blocked" tracking
    for my $ip (keys %{ $self->{already_blocked} }) {
        my $blocked_at = $self->{already_blocked}{$ip};
        if ($now - $blocked_at > $max_age) {
            delete $self->{already_blocked}{$ip};
        }
    }

    if ($cleaned_usernames > 0 || $cleaned_ips > 0 || $reset_offenses > 0) {
        $self->{log}->info(
            "Cleanup: removed $cleaned_usernames usernames, $cleaned_ips IPs, reset $reset_offenses offense counters"
        );
    }
}

1;
