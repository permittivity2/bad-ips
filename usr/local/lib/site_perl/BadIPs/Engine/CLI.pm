package BadIPs::Engine::CLI;

# ============================================================================
# bad-ips 4.0 command line (role mode):
#
#   bad_ips unban <addr> [--hours N] [--reason TEXT]
#   bad_ips ban   <addr> [--for 7d] [--reason TEXT]
#   bad_ips list  [--limit N]
#   bad_ips why   <addr>
#   bad_ips test-rules <logfile> [--rule NAME]
#   bad_ips --test-config            (handled here when a role is set)
#
# unban/ban/list/why talk to the shared ban list, so they work from any host
# that has the database settings; the block role applies the change within
# one reconcile cycle (30 s by default). test-rules touches neither the
# database nor the firewall.
# ============================================================================

use strict;
use warnings;

use Getopt::Long qw(GetOptionsFromArray);
use POSIX qw(strftime);

use BadIPs::Engine::Config;
use BadIPs::Engine::Net qw(parse_addr);
use BadIPs::Engine::Rules;
use BadIPs::Engine::Store;

my %UNIT = (s => 1, m => 60, h => 3600, d => 86400, w => 604800);

sub _when { strftime('%Y-%m-%d %H:%M:%S', localtime $_[0]) }

sub _duration {
    my ($t) = @_;
    my ($n, $u) = ($t // '') =~ /\A(\d+)([smhdw]?)\z/ or return undef;
    return $n * $UNIT{ $u || 's' };
}

sub _by { $ENV{SUDO_USER} || (getpwuid($<))[0] || "uid $<" }

sub _settings {
    my (%a) = @_;
    my ($s, $err) = BadIPs::Engine::Config::load(conf_main => $a{conf_main}, conf_dir => $a{conf_dir});
    if (@$err) { print STDERR "configuration error: $_\n" for @$err; return undef }
    return $s;
}

sub _store {
    my ($s, %a) = @_;
    unless ($s->{db}) { print STDERR "no database settings on this host; run this where the shared list is configured\n"; return undef }
    return BadIPs::Engine::Store->new(db => $s->{db}, host => $s->{host}, connect => $a{connect});
}

sub main {
    my (%a) = @_;
    my @argv = @{ $a{argv} };
    my $cmd  = shift @argv // '';
    return test_rules(%a, argv => \@argv) if $cmd eq 'test-rules';

    my $s = _settings(%a) or return 2;
    my $st = _store($s, %a) or return 2;
    my $now = time;

    if ($cmd eq 'unban') {
        my ($hours, $reason) = (24, undef);
        GetOptionsFromArray(\@argv, 'hours=i' => \$hours, 'reason=s' => \$reason) or return 2;
        my $p = parse_addr($argv[0] // '') or do { print STDERR "usage: bad_ips unban <address> [--hours N] [--reason TEXT]\n"; return 2 };
        my $n = $st->unban($p->{text}, by => _by(), reason => $reason, hours => $hours, now => $now);
        unless (defined $n) { print STDERR "could not reach the shared ban list: ", $st->status, "\n"; return 1 }
        printf "%s: ended %d ban%s; exempt until %s. The edge lifts it within a minute.\n",
            $p->{text}, $n, ($n == 1 ? '' : 's'), _when($now + 3600 * $hours);
        return 0;
    }
    if ($cmd eq 'ban') {
        my ($for, $reason) = ('7d', undef);
        GetOptionsFromArray(\@argv, 'for=s' => \$for, 'reason=s' => \$reason) or return 2;
        my $p = parse_addr($argv[0] // '') or do { print STDERR "usage: bad_ips ban <address> [--for 7d] [--reason TEXT]\n"; return 2 };
        my $secs = _duration($for);
        unless ($secs && $secs >= 60) { print STDERR "--for must be like 90s, 30m, 12h, 7d or 2w (at least a minute)\n"; return 2 }
        if (my $c = $s->{never}->conflict($p)) { print STDERR "$p->{text} is on the never-block list ($c); not banning it\n"; return 1 }
        my $ok = $st->ban($p->{text}, seconds => $secs, reason => $reason // 'manual ban', by => _by(), now => $now);
        unless ($ok) { print STDERR "could not reach the shared ban list: ", $st->status, "\n"; return 1 }
        printf "%s: banned until %s. The edge applies it within a minute.\n", $p->{text}, _when($now + $secs);
        return 0;
    }
    if ($cmd eq 'list') {
        my $limit = 1000;
        GetOptionsFromArray(\@argv, 'limit=i' => \$limit) or return 2;
        my $rows = $st->list($now, limit => $limit);
        unless ($rows) { print STDERR "could not reach the shared ban list: ", $st->status, "\n"; return 1 }
        printf "%-40s %-19s %-19s %s\n", 'ADDRESS', 'LAST SEEN', 'BANNED UNTIL', 'REPORTED BY / RULE';
        printf "%-40s %-19s %-19s %s / %s\n", $_->{ip}, _when($_->{last_seen}), _when($_->{expires}), $_->{servers}, $_->{rules}
            for @$rows;
        # every row carries the count of ALL active bans; a limited list says
        # how many it left out instead of passing the rows shown off as the total
        my $total = @$rows ? $rows->[0]{total} : 0;
        if   ($total > @$rows) { printf "showing %d of %d active bans\n", scalar @$rows, $total }
        else                   { printf "%d active ban%s\n", $total, ($total == 1 ? '' : 's') }
        return 0;
    }
    if ($cmd eq 'why') {
        my $p = parse_addr($argv[0] // '') or do { print STDERR "usage: bad_ips why <address>\n"; return 2 };
        if (my $c = $s->{never}->conflict($p)) { print "$p->{text} is on this host's never-block list ($c): it is never blocked.\n" }
        my $w = $st->why($p->{text}, $now);
        unless ($w) { print STDERR "could not reach the shared ban list: ", $st->status, "\n"; return 1 }
        if (!@{ $w->{bans} } && !@{ $w->{exemptions} }) { print "$p->{text}: never reported.\n"; return 0 }
        for my $b (@{ $w->{bans} }) {
            printf "%s: %s by %s (rule %s, %s), %s %s; reported %d time%s, first %s\n",
                $p->{text}, ($b->{expires} > $now ? 'BANNED' : 'was banned'), $b->{server}, $b->{rule} // '?',
                $b->{summary} // '', ($b->{expires} > $now ? 'until' : 'ended'), _when($b->{expires}),
                $b->{times}, ($b->{times} == 1 ? '' : 's'), _when($b->{first});
            print "    $_\n" for grep { length } split /\n/, ($b->{evidence} // '');
        }
        for my $e (@{ $w->{exemptions} }) {
            printf "%s: exempt (%s) %s %s, by %s: %s\n", $p->{text}, $e->{ip},
                ($e->{until} > $now ? 'until' : 'ended'), _when($e->{until}), $e->{by} // '?', $e->{reason} // '';
        }
        return 0;
    }
    print STDERR "unknown command '$cmd' (unban, ban, list, why, test-rules)\n";
    return 2;
}

=head2 test_rules(conf_main, conf_dir, argv => [file, --rule NAME])

Runs the configured rules over a log file and prints what WOULD be
detected. No database, no firewall. Rules run regardless of their own
source paths, so one sample file can be checked against all of them.

=cut

sub test_rules {
    my (%a) = @_;
    my @argv = @{ $a{argv} };
    my $only;
    GetOptionsFromArray(\@argv, 'rule=s' => \$only) or return 2;
    my $file = $argv[0] or do { print STDERR "usage: bad_ips test-rules <logfile> [--rule NAME]\n"; return 2 };
    my ($s, $err) = BadIPs::Engine::Config::load(conf_main => $a{conf_main}, conf_dir => $a{conf_dir});
    # the role does not matter here; only rule errors do
    my @rerr = grep { /^rule / } @$err;
    if (@rerr) { print STDERR "configuration error: $_\n" for @rerr; return 2 }
    my @rules = grep { !$only || $_->{name} eq $only } @{ $s->{rules} || [] };
    unless (@rules) { print STDERR "no matching rules\n"; return 2 }
    open(my $fh, '<:raw', $file) or do { print STDERR "cannot read $file: $!\n"; return 2 };
    my %c = map { $_->{name} => BadIPs::Engine::Counter->new(rule => $_) } @rules;
    my (%n, %never);
    my $now = time;
    while (my $line = <$fh>) {
        $line =~ s/\r?\n\z//;
        for my $r (@rules) {
            my ($ip, $w) = BadIPs::Engine::Rules::match_line($r, $line) or next;
            $n{ $r->{name} }{matched}++;
            if ($s->{never}->conflict($ip)) { $never{ $r->{name} }{$ip}++; next }
            my $t = BadIPs::Engine::Rules::line_time($line, $r->{format}, $now) // next;
            my $d = $c{ $r->{name} }->observe($ip, $t, $w, $line) or next;
            $n{ $r->{name} }{detected}++;
            printf "%s  %-16s %-39s %d hits  %s .. %s  ban %ds\n", ($d->{expires} > $now ? 'WOULD BAN' : 'would ban (over)'),
                $r->{name}, $d->{ip}, $d->{hits}, _when($d->{first}), _when($d->{last}), $r->{ban};
        }
    }
    for my $r (@rules) {
        my $x = $n{ $r->{name} } || {};
        printf "%-22s matched %d line%s, %d detection%s%s\n", $r->{name}, $x->{matched} // 0, (($x->{matched} // 0) == 1 ? '' : 's'),
            $x->{detected} // 0, (($x->{detected} // 0) == 1 ? '' : 's'),
            ($never{ $r->{name} } ? '; never-block skipped: ' . join(', ', map { "$_ x$never{ $r->{name} }{$_}" } sort keys %{ $never{ $r->{name} } }) : '');
    }
    return 0;
}

=head2 test_config(conf_main, conf_dir)

Prints the role-mode configuration as the daemon would run it; exits 1 on
errors. Also checks that the shared ban list is reachable.

=cut

sub test_config {
    my (%a) = @_;
    my ($s, $err, $notes) = BadIPs::Engine::Config::load(conf_main => $a{conf_main}, conf_dir => $a{conf_dir});
    my $from = sub { my $f = ($s->{from} || {})->{ $_[0] }; return $f ? "  (from $f)" : '' };
    printf "role:        %s%s%s\n", $s->{role} // '?', ($s->{dry_run} ? ' (watch mode: the firewall is never touched)' : ''), $from->('role');
    printf "host:        %s\n", $s->{host} // '?';
    if (($s->{role} // '') eq 'block') {
        printf "drops on:    %s\n", @{ $s->{block_interfaces} || [] } ? join(', ', @{ $s->{block_interfaces} }) : 'every interface';
        printf "dns:         %s\n", $s->{dns_accept} ? 'never blocked' : 'blocked like anything else';
    }
    if ($s->{never}) {
        print  "never-block: ", join(', ', $s->{never}->cidrs), $from->('never_block_cidrs'), "\n";
    }
    printf "rules:       %d\n", scalar @{ $s->{rules} || [] };
    for my $r (@{ $s->{rules} || [] }) {
        my $missing = $r->{journal} ? '' : join('', map { -e $_ ? '' : " ($_ not present here)" } @{ $r->{files} });
        printf "  %-22s %d in %ds -> ban %ds, from %s%s\n", $r->{name}, $r->{count}, $r->{window}, $r->{ban},
            ($r->{journal} ? "journal unit $r->{journal}" : join(', ', @{ $r->{files} })), $missing;
    }
    printf "feeds:       %s\n", join(', ', map { $_->{name} } @{ $s->{feeds} || [] }) || 'none';
    if ($s->{db}) {
        printf "database:    %s:%s/%s as %s, schema %s%s\n", @{ $s->{db} }{qw(host port name user)}, $s->{db}{schema} // '(default)',
            $from->('db_host');
        if (!@$err) {
            my $st = BadIPs::Engine::Store->new(db => $s->{db}, host => $s->{host}, connect => $a{connect});
            my $act = $st->load_active(time);
            printf "             %s\n", defined $act ? sprintf('reachable; %d active ban%s', scalar keys %$act, (keys %$act == 1 ? '' : 's'))
                                                     : 'NOT reachable: ' . $st->status;
        }
    }
    else {
        print "database:    none (local only)\n";
    }
    print "note:        $_\n" for @$notes;
    print "ERROR:       $_\n" for @$err;
    print @$err ? "configuration has errors; the daemon would refuse to start\n" : "configuration OK\n";
    return @$err ? 1 : 0;
}

1;
