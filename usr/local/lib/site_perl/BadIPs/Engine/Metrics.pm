package BadIPs::Engine::Metrics;

# ============================================================================
# bad-ips 4.0 role mode: numbers for Prometheus.
#
# Every `metrics_interval` seconds the daemon writes one file, badips.prom, to
# node_exporter's textfile directory (the same drop-a-file route the web apps
# use). No new port, no firewall change, no new scrape job. The file is
# written whole to a temporary name and renamed, so a scrape never sees half.
#
# Publishing is best effort: a directory that is missing or not writable is
# logged once and never stops the daemon. (The directory is group `homelab`;
# the package puts the service user in that group.)
#
# Counters are since the daemon started; Prometheus' rate()/increase() handle
# the reset. "Knocks" are packets the firewall dropped, not people: a refused
# computer retries a few times.
# ============================================================================

use strict;
use warnings;

use Sys::Hostname ();

our $VERSION = '4.3.0';

my %MODE = (off => 0, report => 1);

sub _esc { my ($v) = @_; $v =~ s/([\\"])/\\$1/g; $v =~ s/\n/\\n/g; $v }

# Returns the text of the metrics file for the engine's current state.
sub render {
    my ($e, $now, $fw) = @_;
    my $s = $e->{s};
    my $st = $e->{stats};
    my (@out, %seen);
    my $m = sub {    # name, type, help, value, [labels hash]
        my ($name, $type, $help, $val, $lab) = @_;
        unless ($seen{$name}++) { push @out, "# HELP $name $help", "# TYPE $name $type" }
        my $l = $lab && %$lab ? '{' . join(',', map { qq{$_="} . _esc($lab->{$_}) . '"' } sort keys %$lab) . '}' : '';
        push @out, "$name$l " . (defined $val ? $val : 0);
    };

    my $mode = $s->{role} eq 'block' ? ($s->{dry_run} ? 2 : 3) : ($MODE{ $s->{role} } // 0);
    $m->('badips_info', 'gauge', 'bad-ips role and version', 1, { role => $s->{role}, version => $VERSION });
    $m->('badips_mode', 'gauge', '0 off, 1 report, 2 block role in watch mode (blocks nothing), 3 block', $mode);
    $m->('badips_log_lines_total', 'counter', 'Log lines read', $st->{lines});
    $m->('badips_log_matches_total', 'counter', 'Log lines that matched a rule', $st->{matches});
    $m->('badips_detections_total', 'counter', 'Addresses newly caught by a rule', $st->{detections});
    $m->('badips_detections_by_rule_total', 'counter', 'Addresses newly caught, by rule', $e->{by_rule}{$_}, { rule => $_ })
        for sort keys %{ $e->{counters} || {} };
    $m->('badips_reports_pushed_total', 'counter', 'Detections sent to the shared list', $st->{pushed});
    $m->('badips_reports_dropped_total', 'counter', 'Detections discarded because the queue was full', $st->{dropped});
    $m->('badips_never_block_refusals_total', 'counter',
         'Times a never-block address was caught by a rule or listed, and left alone (should stay 0 for house addresses)',
         $st->{never_skipped} + ($e->{never_refused} // 0));
    $m->('badips_exempt_skipped_total', 'counter', 'Detections ignored because the address was unbanned by hand', $st->{exempt_skipped});
    $m->('badips_queue_length', 'gauge', 'Detections waiting to be sent to the shared list', scalar @{ $e->{queue} });
    $m->('badips_exemptions_active', 'gauge', 'Hand unbans (exemptions) still running', scalar keys %{ $e->{exempt} || {} });
    $m->('badips_database_up', 'gauge', 'This node is connected to the shared list (1) or not (0)',
         ($e->{store} && $e->{store}{dbh}) ? 1 : 0);

    if ($s->{role} eq 'block') {
        my $c = $e->{last_counts} || {};
        $m->('badips_blocked_addresses', 'gauge', 'Addresses on the ban list this node enforces (or would, in watch mode)', $c->{bans});
        $m->('badips_feed_ranges', 'gauge', 'Public-blocklist (Spamhaus etc.) ranges this node enforces', $c->{feed});
        $m->('badips_seconds_since_sync', 'gauge', 'Seconds since the firewall was last brought in line with the shared list',
             defined $e->{last_sync} ? $now - $e->{last_sync} : -1);
        $m->('badips_firewall_rebuilds_total', 'counter', 'Times the whole firewall table was rebuilt', $e->{fw_rebuilds} // 0);
        $m->('badips_feed_age_seconds', 'gauge', 'Age of the oldest cached copy of a public blocklist', $_->age($now), { feed => $_->name })
            for @{ $e->{feeds} || [] };
        if ($fw && $fw->{exists} && !$fw->{error}) {
            my $p = $fw->{packets} || {};
            my (%group, $listed);
            for my $l (qw(ban4 ban6 feed4 feed6)) {
                my $total = $p->{"badips:$l"} // 0;
                $m->('badips_drops_total', 'counter', 'Packets the firewall dropped, by list', $total, { list => $l });
                my $named = 0;
                for my $g (@BadIPs::Engine::Firewall::KNOCK_GROUPS) {
                    my $n = $p->{"badips:knock:$l:$g"} // 0;
                    $group{$g} += $n;
                    $named += $n;
                }
                $group{other} += $total > $named ? $total - $named : 0;
            }
            $m->('badips_knocks_total', 'counter', 'Packets dropped, by the port group asked for (web 80/443, smtp 25, submission 465/587, imap 110/143/993/995, ssh 22, other)',
                 $group{$_} // 0, { group => $_ }) for (@BadIPs::Engine::Firewall::KNOCK_GROUPS, 'other');
            $m->('badips_ssh_connection_attempts_total', 'counter', 'Every SSH (22) packet reaching the public interfaces, banned or not',
                 $p->{'badips:knock_all:ssh'});
            $m->('badips_banned_addresses_still_knocking', 'gauge', 'Banned addresses that have sent a packet since being banned',
                 ($fw->{sets}{badipv4}{knocking} // 0) + ($fw->{sets}{badipv6}{knocking} // 0));
        }
    }
    $m->('badips_metrics_timestamp_seconds', 'gauge', 'When this file was written', $now);
    return join("\n", @out) . "\n";
}

# Writes the file; returns 1, or 0 with $e->{metrics_err} set.
sub publish {
    my ($e, $now) = @_;
    my $dir = $e->{s}{metrics_dir};
    return 1 unless defined $dir && length $dir;
    my $fw = $e->{firewall} ? $e->{firewall}->state : undef;
    my $text = render($e, $now, $fw);
    my ($tmp, $final) = ("$dir/.badips.prom.tmp", "$dir/badips.prom");
    my $fh;
    my $ok = open($fh, '>', $tmp) && print({$fh} $text) && close($fh) && chmod(0644, $tmp) && rename($tmp, $final);
    unless ($ok) {
        my $err = "cannot write $final: $!";
        $e->logger->warn("metrics: $err") if ($e->{metrics_err} // '') ne $err;
        $e->{metrics_err} = $err;
        unlink $tmp;
        return 0;
    }
    $e->{metrics_err} = undef;
    return 1;
}

1;
