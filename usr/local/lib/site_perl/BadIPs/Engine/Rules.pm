package BadIPs::Engine::Rules;

# ============================================================================
# The rule engine for role mode (bad-ips 4.0).
#
# A rule is one [rule:NAME] config section:
#
#   [rule:smtp-auth]
#   source  = /var/log/mail.log          ; one or more files of the same format
#   match   = ^\S+ \S+ postfix/(?:submission/)?smtpd\[\d+\]: warning: [^\s\[\]]+\[(?<ip>[0-9A-Fa-f.:]+)\]: SASL \S+ authentication failed
#   count   = 5                          ; this many hits ...
#   window  = 600                        ; ... within this many seconds
#   ban     = 3600                       ; bans for this long
#   service = smtp
#
# The pattern MUST name the client address with (?<ip>...), and it is the
# pattern's job to anchor that capture at a fixed place in the line. Taking
# "the first thing that looks like an address" lets an attacker type an
# address into a username or URL and get an innocent server banned, which
# is exactly what the 3.x extractor allowed. An optional (?<n>\d+) capture
# counts a line as n hits (e.g. dovecot's "N attempts"), capped at
# max_weight.
#
# Time windows use the log line's OWN timestamp, never the clock at read
# time, so re-reading a log after a restart cannot turn an old burst into a
# fresh one.
# ============================================================================

use strict;
use warnings;

use Time::Local qw(timegm);
use BadIPs::Engine::Net qw(parse_addr);

my %MON = (Jan => 0, Feb => 1, Mar => 2, Apr => 3, May => 4, Jun => 5,
           Jul => 6, Aug => 7, Sep => 8, Oct => 9, Nov => 10, Dec => 11);

my %FORMATS = map { $_ => 1 } qw(auto rfc3339 nginx syslog journal);

=head2 compile_rule($name, \%section)

Returns ($rule, \@errors). On any error $rule is undef: a rule that is
half-understood is never run.

=cut

sub compile_rule {
    my ($name, $c) = @_;
    my @err;
    my %r = (name => $name);

    my $match = $c->{match} // '';
    if (!length $match) {
        push @err, "match is required";
    }
    else {
        my $re = eval { qr/$match/ };
        if (!$re) {
            (my $e = $@) =~ s/\s+at \S+ line \d+.*//s;
            push @err, "match does not compile: $e";
        }
        elsif ($match !~ /\(\?<ip>/) {
            push @err, "match must capture the client address as (?<ip>...)";
        }
        else {
            $r{re} = $re;
            $r{has_weight} = $match =~ /\(\?<n>/ ? 1 : 0;
        }
    }

    my @files = grep { length } split /\s*,\s*/, ($c->{source} // '');
    my $journal = $c->{journal} // '';
    if (@files && length $journal) {
        push @err, "use either source (files) or journal (one unit), not both";
    }
    elsif (!@files && !length $journal) {
        push @err, "source (a log file) or journal (a unit) is required";
    }
    for my $f (@files) {
        push @err, "source '$f' must be an absolute path" unless $f =~ m{\A/};
    }
    push @err, "journal '$journal' is not a valid unit name"
        if length $journal && $journal !~ /\A[A-Za-z0-9@_.:-]+\z/;
    $r{files}   = \@files;
    $r{journal} = $journal;

    for my $k (qw(count window ban)) {
        my $v = $c->{$k};
        if (!defined $v || $v !~ /\A\d+\z/ || $v < 1) {
            push @err, "$k must be a whole number of at least 1";
        }
        else {
            $r{$k} = $v + 0;
        }
    }
    push @err, "ban must be at least 60 seconds"      if defined $r{ban}    && $r{ban} < 60;
    push @err, "ban must be at most 365 days"         if defined $r{ban}    && $r{ban} > 365 * 86400;
    push @err, "window must be at most 7 days"        if defined $r{window} && $r{window} > 7 * 86400;

    my $fmt = $c->{format} // ($journal ? 'journal' : 'auto');
    push @err, "format must be one of: " . join(', ', sort keys %FORMATS) unless $FORMATS{$fmt};
    $r{format} = $fmt;

    my $mw = $c->{max_weight} // 10;
    push @err, "max_weight must be a whole number of at least 1" unless $mw =~ /\A\d+\z/ && $mw >= 1;
    $r{max_weight} = $mw + 0;

    $r{service} = $c->{service} // $name;

    return (undef, \@err) if @err;
    return (\%r, []);
}

=head2 match_line($rule, $line)

Returns (ip, weight) if the line matches and names a valid single host,
else the empty list.

=cut

sub match_line {
    my ($rule, $line) = @_;
    return () unless $line =~ $rule->{re};
    my $ip = $+{ip};
    my $n  = $+{n};
    my $p  = parse_addr($ip) or return ();
    my $w  = 1;
    if ($rule->{has_weight} && defined $n && $n =~ /\A\d+\z/) {
        $w = $n < 1 ? 1 : ($n > $rule->{max_weight} ? $rule->{max_weight} : $n + 0);
    }
    return ($p->{text}, $w);
}

=head2 line_time($line, $format, $now)

The line's own timestamp as epoch seconds, or undef if it carries none
the format understands. C<$now> is used only to pick the year for the
year-less traditional syslog format.

=cut

sub line_time {
    my ($line, $format, $now) = @_;
    $format //= 'auto';
    if ($format eq 'rfc3339' || $format eq 'auto') {
        # 2026-11-02T15:34:30.031181-06:00 host prog[pid]: ...
        if ($line =~ /\A(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|[+-]\d\d:?\d\d)/) {
            my $t = eval { timegm($6, $5, $4, $3, $2 - 1, $1) };
            return defined $t ? $t - _offset($7) : undef;
        }
        return undef if $format eq 'rfc3339';
    }
    if ($format eq 'nginx' || $format eq 'auto') {
        # ... [02/Nov/2026:12:59:38 -0600] "GET / HTTP/1.1" ...
        if ($line =~ /\[(\d\d)\/(\w{3})\/(\d{4}):(\d\d):(\d\d):(\d\d) ([+-]\d{4})\]/ && exists $MON{$2}) {
            my $t = eval { timegm($6, $5, $4, $1, $MON{$2}, $3) };
            return defined $t ? $t - _offset($7) : undef;
        }
        return undef if $format eq 'nginx';
    }
    if ($format eq 'syslog' || $format eq 'auto') {
        # Nov  2 15:34:30 host prog[pid]: ...   (local time, no year)
        if ($line =~ /\A(\w{3}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) / && exists $MON{$1}) {
            $now //= time;
            my $year = (localtime $now)[5] + 1900;
            my $t = eval { Time::Local::timelocal($5, $4, $3, $2, $MON{$1}, $year) };
            # A December line read in early January belongs to last year.
            $t = eval { Time::Local::timelocal($5, $4, $3, $2, $MON{$1}, $year - 1) }
                if defined $t && $t > $now + 86400;
            return $t;
        }
    }
    return undef;
}

sub _offset {
    my ($z) = @_;
    return 0 if !defined $z || $z eq 'Z';
    my ($sign, $h, $m) = $z =~ /\A([+-])(\d\d):?(\d\d)\z/ or return 0;
    my $s = $h * 3600 + $m * 60;
    return $sign eq '-' ? -$s : $s;
}

# ----------------------------------------------------------------------------
# Per-rule counting
# ----------------------------------------------------------------------------

package BadIPs::Engine::Counter;

use strict;
use warnings;

=head2 BadIPs::Engine::Counter->new(rule => $rule)

Tracks hits per address for one rule. observe() returns a detection
hashref when an address reaches the rule's count within its window, and
undef otherwise.

=cut

sub new {
    my ($class, %a) = @_;
    return bless {
        rule        => $a{rule},
        max_tracked => $a{max_tracked} // 50_000,
        hits        => {},   # ip => { events => [[ts, w], ...], lines => [...] }
        reported    => {},   # ip => expiry of the last detection we returned
    }, $class;
}

sub observe {
    my ($self, $ip, $ts, $weight, $line) = @_;
    my $r = $self->{rule};
    my $h = $self->{hits}{$ip} //= { events => [], lines => [], newest => $ts };

    $h->{newest} = $ts if $ts > $h->{newest};
    push @{ $h->{events} }, [ $ts, $weight ];
    push @{ $h->{lines} }, $line;
    shift @{ $h->{lines} } while @{ $h->{lines} } > 5;

    # Lines from two files can arrive out of time order, so the window is
    # measured back from the newest hit seen, not from this one.
    my $cut = $h->{newest} - $r->{window};
    @{ $h->{events} } = grep { $_->[0] > $cut } @{ $h->{events} };

    my $sum = 0;
    $sum += $_->[1] for @{ $h->{events} };

    if ($sum < $r->{count}) {
        $self->_trim($h->{newest}) if keys %{ $self->{hits} } > $self->{max_tracked};
        return undef;
    }

    my $first = $h->{events}[0][0];
    for (@{ $h->{events} }) { $first = $_->[0] if $_->[0] < $first }
    my @lines = @{ $h->{lines} };
    delete $self->{hits}{$ip};

    my $expires = int($h->{newest}) + $r->{ban};
    # Already reported, and that ban still has more than half to run:
    # re-reporting would only rewrite the same row.
    my $prev = $self->{reported}{$ip};
    return undef if defined $prev && $prev - $h->{newest} > $r->{ban} / 2;
    $self->{reported}{$ip} = $expires;

    return {
        ip      => $ip,
        rule    => $r->{name},
        service => $r->{service},
        first   => int($first),
        last    => int($h->{newest}),
        expires => $expires,
        hits    => $sum,
        lines   => \@lines,
    };
}

# Drop addresses whose hits are all older than a window: they can no
# longer reach the count. Bounds memory under a flood of one-hit sources.
sub _trim {
    my ($self, $now) = @_;
    my $hits = $self->{hits};
    my $cut  = $now - $self->{rule}{window};
    for my $ip (keys %$hits) {
        delete $hits->{$ip} if $hits->{$ip}{newest} <= $cut;
    }
    # Still over the cap (many distinct sources inside one window): drop the
    # least recently seen down to 90% of it.
    my $cap = $self->{max_tracked};
    if (keys %$hits > $cap) {
        my @old = sort { $hits->{$a}{newest} <=> $hits->{$b}{newest} } keys %$hits;
        delete @{$hits}{ @old[ 0 .. $#old - int($cap * 0.9) ] };
    }
}

=head2 expire($now)

Forgets reported-ban expiries that have passed. Call now and then.

=cut

sub expire {
    my ($self, $now) = @_;
    for my $ip (keys %{ $self->{reported} }) {
        delete $self->{reported}{$ip} if $self->{reported}{$ip} <= $now;
    }
    $self->_trim($now);
}

1;
