package BadIPs::Engine::Firewall;

# ============================================================================
# The block role's firewall (bad-ips 4.0): keeps the kernel's `inet badips`
# table equal to what it should be, through the privileged helper
# bad_ips_nft (state / sync).
#
# reconcile() is called every reconcile_interval. It reads the table and:
#   * REBUILDS it in one atomic transaction when it is missing (an nftables
#     reload with `flush ruleset`), its structure differs, the settings
#     changed, or a never-block set lost entries;
#   * otherwise applies only the differences: missing bans added, bans that
#     ended or were unbanned removed, bans the kernel will drop too early
#     re-extended, and the feed sets reloaded when the feed changed.
#
# 3.x checked only that the table existed, so a reload silently lifted every
# ban until the daemon happened to re-add each address (up to 8 days later).
# ============================================================================

use strict;
use warnings;

use JSON ();
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempfile);
use IPC::Open3 qw(open3);
use BadIPs::Engine::Net qw(parse_cidr);

my $MAX_TTL = 30 * 86400;    # the helper caps element timeouts at this

sub new {
    my ($class, %a) = @_;
    return bless {
        helper     => $a{helper} // '/usr/local/sbin/bad_ips_nft',
        sudo       => $a{sudo} // 1,
        runner     => $a{runner},          # tests: sub { my ($args, $stdin) = @_; return ($rc, $stdout, $stderr) }
        log        => $a{log},
        ifaces     => $a{ifaces} || [],
        dns_accept => $a{dns_accept} // 1,
        never      => $a{never},           # BadIPs::Engine::NeverBlock
        applied    => undef,               # what the last successful replace/apply left behind
    }, $class;
}

sub _log { my ($self, $lvl, $m) = @_; $self->{log}->$lvl($m) if $self->{log} }

sub _run {
    my ($self, $args, $stdin) = @_;
    return $self->{runner}->($args, $stdin) if $self->{runner};
    my @cmd = ($self->{sudo} ? ('sudo', '-n') : (), $self->{helper}, @$args);
    # stderr goes to a temp file and the request is written in full before
    # stdout is read: the helper reads all of stdin before writing anything,
    # so neither pipe can fill up and deadlock.
    my $efh = tempfile();
    my ($in, $out);
    my $pid = eval { open3($in, $out, '>&' . fileno($efh), @cmd) };
    return (127, '', "cannot run $cmd[0]: $@") unless $pid;
    print {$in} $stdin if defined $stdin;
    close $in;
    my $stdout = do { local $/; <$out> } // '';
    waitpid($pid, 0);
    my $rc = $? >> 8;
    seek($efh, 0, 0);
    my $stderr = do { local $/; <$efh> } // '';
    $stderr =~ s/\s+\z//;
    return ($rc, $stdout, $stderr);
}

# ----------------------------------------------------------------------------
# Reading the table
# ----------------------------------------------------------------------------

sub _elem_value {
    my ($e) = @_;
    return ($e, undef) unless ref $e;
    if (ref $e eq 'HASH') {
        if (exists $e->{elem}) {
            my ($v) = _elem_value($e->{elem}{val});
            return ($v, $e->{elem}{expires});
        }
        return ("$e->{prefix}{addr}/$e->{prefix}{len}", undef) if $e->{prefix};
        return (join('-', @{ $e->{range} }), undef) if $e->{range};
    }
    return (undef, undef);
}

=head2 state

{ exists => 0 } when the table is absent; otherwise
{ exists => 1, sets => { name => { type, flags => [..], elems => { value => expires|undef },
  counter => 0|1, knocking => N } }, chain => { hook, prio, policy } | undef, rules => [ comment, ... ],
  packets => { comment => N } }. "knocking" is how many elements of a ban set have
counted a packet since they were added; "packets" is each counting rule's total.
{ error => ... } when the helper itself failed.

=cut

sub state {
    my ($self) = @_;
    my ($rc, $out, $err) = $self->_run(['state']);
    if ($rc != 0) {
        return { exists => 0 } if $err =~ /No such file or directory|does not exist/i;
        return { error => "bad_ips_nft state failed ($rc): $err" };
    }
    my $j = eval { JSON->new->decode($out) } or return { error => "cannot parse nft output: $@" };
    my %st = (exists => 0, sets => {}, rules => []);
    for my $o (@{ $j->{nftables} || [] }) {
        if (my $t = $o->{table}) { $st{exists} = 1 if $t->{family} eq 'inet' && $t->{name} eq 'badips' }
        elsif (my $s = $o->{set}) {
            next unless $s->{table} eq 'badips';
            my (%el, $knocking);
            for my $e (@{ $s->{elem} || [] }) {
                my ($v, $exp) = _elem_value($e);
                $el{$v} = $exp if defined $v;
                $knocking++ if defined $v && ref $e eq 'HASH' && ref $e->{elem} eq 'HASH' && ref $e->{elem}{counter} && $e->{elem}{counter}{packets};
            }
            $st{sets}{ $s->{name} } = { type => $s->{type}, flags => [ sort @{ $s->{flags} || [] } ], elems => \%el,
                                        counter => (grep { exists $_->{counter} } @{ $s->{stmt} || [] }) ? 1 : 0,
                                        knocking => $knocking // 0 };
        }
        elsif (my $c = $o->{chain}) {
            next unless $c->{table} eq 'badips' && $c->{name} eq 'preroute_block';
            $st{chain} = { hook => $c->{hook} // '', prio => $c->{prio} // '', policy => $c->{policy} // '' };
        }
        elsif (my $r = $o->{rule}) {
            next unless $r->{table} eq 'badips' && $r->{chain} eq 'preroute_block';
            push @{ $st{rules} }, $r->{comment} // '';
            for my $x (@{ $r->{expr} || [] }) {
                $st{packets}{ $r->{comment} // '' } = $x->{counter}{packets} if ref $x->{counter};
            }
        }
    }
    return \%st;
}

# Counting-only rules (metrics, item 43), in the order bad_ips_nft writes them.
our @KNOCK_LISTS  = qw(ban4 ban6 feed4 feed6);
our @KNOCK_GROUPS = qw(web smtp submission imap ssh);

sub expected_rules {
    my ($self) = @_;
    return [ (@{ $self->{ifaces} } ? 'badips:iface' : ()), 'badips:never4', 'badips:never6',
             ($self->{dns_accept} ? 'badips:dns' : ()), 'badips:knock_all:ssh',
             (map { my $l = $_; map { "badips:knock:$l:$_" } @KNOCK_GROUPS } @KNOCK_LISTS),
             qw(badips:ban4 badips:ban6 badips:feed4 badips:feed6) ];
}

my %SETDEF = (
    badipv4        => [ 'ipv4_addr', 'timeout' ],
    badipv6        => [ 'ipv6_addr', 'timeout' ],
    feedv4         => [ 'ipv4_addr', 'interval' ],
    feedv6         => [ 'ipv6_addr', 'interval' ],
    never_block    => [ 'ipv4_addr', 'interval' ],
    never_block_v6 => [ 'ipv6_addr', 'interval' ],
);

sub _structure_problem {
    my ($self, $st) = @_;
    for my $name (sort keys %SETDEF) {
        my $s = $st->{sets}{$name} or return "set $name missing";
        my ($type, $flag) = @{ $SETDEF{$name} };
        return "set $name has type $s->{type}" if $s->{type} ne $type;
        return "set $name has flags @{ $s->{flags} }" if "@{ $s->{flags} }" ne $flag;
        return "set $name does not count elements" if $name =~ /\Abadipv[46]\z/ && !$s->{counter};
    }
    for my $name (keys %{ $st->{sets} }) { return "unexpected set $name" unless $SETDEF{$name} }
    my $c = $st->{chain} or return 'chain missing';
    return "chain is $c->{hook}/$c->{prio}/$c->{policy}"
        unless $c->{hook} eq 'prerouting' && "$c->{prio}" eq '-150' && $c->{policy} eq 'accept';
    my $want = join ',', @{ $self->expected_rules };
    my $have = join ',', @{ $st->{rules} };
    return "rules are [$have]" if $have ne $want;
    return undef;
}

# ----------------------------------------------------------------------------
# Making it right
# ----------------------------------------------------------------------------

sub _never_cidrs {    # the never-block list without entries contained in another
    my ($self, $fam) = @_;
    return minimize($self->{never}->cidrs($fam));
}

=head2 minimize(@cidrs)

Drops entries contained in (or equal to) another entry, so an interval set
gets no overlapping elements (nft refuses overlaps) and its element count
is predictable.

=cut

sub minimize {
    my @p = sort { $a->{fam} <=> $b->{fam} || $a->{net} cmp $b->{net} || $a->{len} <=> $b->{len} }
            grep { defined } map { parse_cidr($_) } @_;
    my (@keep, $cur);
    for my $p (@p) {
        next if $cur && BadIPs::Engine::Net::overlaps($cur, $p) && $cur->{len} <= $p->{len};
        push @keep, $p;
        $cur = $p;
    }
    return map { $_->{text} } @keep;
}

sub _infra_fp {
    my ($self) = @_;
    return md5_hex(join '|', join(',', @{ $self->{ifaces} }), $self->{dns_accept},
                   $self->_never_cidrs(4), $self->_never_cidrs(6));
}

sub _fam { $_[0] =~ /:/ ? 6 : 4 }

=head2 reconcile(bans => { addr => expires }, feed => [cidrs], now => $epoch)

Returns { ok => 1, replaced => reason|undef, added => N, removed => N,
feed_reloaded => 0|1 } or { ok => 0, error => ... }.

=cut

sub reconcile {
    my ($self, %a) = @_;
    my $now  = $a{now} // time;
    my $bans = $a{bans} || {};
    my @feed = minimize(@{ $a{feed} || [] });
    my $feed_v = md5_hex(join "\n", @feed);

    my $st = $self->state;
    return { ok => 0, error => $st->{error} } if $st->{error};

    my $app = $self->{applied};
    my $why;
    if    (!$st->{exists})                              { $why = 'table missing' }
    elsif (my $p = $self->_structure_problem($st))      { $why = "structure differs: $p" }
    elsif (!$app || $app->{infra} ne $self->_infra_fp)  { $why = $app ? 'settings changed' : 'first reconcile since start' }
    elsif (keys %{ $st->{sets}{never_block}{elems} } != $app->{count}{never_block}
        || keys %{ $st->{sets}{never_block_v6}{elems} } != $app->{count}{never_block_v6}) {
        $why = 'never-block entries missing';
    }
    return $self->_replace($bans, \@feed, $feed_v, $now, $why) if $why;

    my (@ban, @unban);
    for my $set (qw(badipv4 badipv6)) {
        my $fam = $set eq 'badipv4' ? 4 : 6;
        my $k = $st->{sets}{$set}{elems};
        for my $ip (grep { _fam($_) == $fam } keys %$bans) {
            my $rem = $bans->{$ip} - $now;
            next if $rem < 10;
            $rem = $MAX_TTL if $rem > $MAX_TTL;
            if (!exists $k->{$ip}) {
                push @ban, "ban $ip $rem";
            }
            elsif (defined $k->{$ip} && $k->{$ip} + 300 < $rem) {
                # the kernel would drop it noticeably early (an extended ban,
                # or a ban longer than the timeout cap): re-add it longer
                push @unban, "unban $ip";
                push @ban, "ban $ip $rem";
            }
        }
        for my $ip (keys %$k) {
            push @unban, "unban $ip" unless exists $bans->{$ip} && $bans->{$ip} - $now >= 10;
        }
    }
    my $feedreset = $app->{feed} ne $feed_v
        || keys %{ $st->{sets}{feedv4}{elems} } != $app->{count}{feedv4}
        || keys %{ $st->{sets}{feedv6}{elems} } != $app->{count}{feedv6};

    return { ok => 1, added => 0, removed => 0, feed_reloaded => 0 } unless @ban || @unban || $feedreset;

    my %gone = map { (split ' ')[1] => 1 } @unban;
    my $extended = grep { $gone{ (split ' ')[1] } } @ban;
    my %result = (ok => 1, added => @ban - $extended, removed => keys(%gone) - $extended,
                  extended => $extended, feed_reloaded => $feedreset ? 1 : 0);

    my $req = "mode apply\n";
    $req .= "feedreset\n" . join('', map { "feed $_\n" } @feed) if $feedreset;
    $req .= join('', map { "$_\n" } @unban, @ban);
    my ($rc, undef, $err) = $self->_run(['sync'], $req);
    if ($rc != 0) {
        $self->_log(warn => "firewall: applying changes failed ($err); rebuilding the table instead");
        return $self->_replace($bans, \@feed, $feed_v, $now, 'apply failed');
    }
    if ($feedreset) {
        # nft may merge adjacent ranges, so record what it actually holds
        my $after = $self->state;
        $app->{feed} = $feed_v;
        $app->{count}{$_} = scalar keys %{ $after->{sets}{$_}{elems} || {} } for qw(feedv4 feedv6);
    }
    return \%result;
}

=head2 remove_if_present

Drops the table (and its persistent file) if it exists. For hosts that must
not block: role report, or watch mode. Returns 1 if it removed one.

=cut

sub remove_if_present {
    my ($self) = @_;
    my $st = $self->state;
    return 0 if $st->{error} || !$st->{exists};
    my ($rc, undef, $err) = $self->_run(['remove']);
    if ($rc != 0) { $self->_log(error => "firewall: could not remove the table: $err"); return 0 }
    $self->{applied} = undef;
    $self->_log(info => 'firewall: removed the inet badips table (this host does not block)');
    return 1;
}

sub _replace {
    my ($self, $bans, $feed, $feed_v, $now, $why) = @_;
    my $req = "mode replace\n";
    $req .= "iface $_\n" for @{ $self->{ifaces} };
    $req .= "dns_accept $self->{dns_accept}\n";
    $req .= "never $_\n" for $self->_never_cidrs(4), $self->_never_cidrs(6);
    $req .= "feed $_\n" for @$feed;
    for my $ip (sort keys %$bans) {
        my $rem = $bans->{$ip} - $now;
        next if $rem < 10;
        $rem = $MAX_TTL if $rem > $MAX_TTL;
        $req .= "ban $ip $rem\n";
    }
    my ($rc, undef, $err) = $self->_run(['sync'], $req);
    if ($rc != 0) {
        $self->{applied} = undef;
        return { ok => 0, error => "rebuilding the table failed: $err" };
    }
    my $after = $self->state;
    if ($after->{error} || !$after->{exists}) {
        $self->{applied} = undef;
        return { ok => 0, error => 'table missing right after rebuilding it' };
    }
    $self->{applied} = {
        infra => $self->_infra_fp,
        feed  => $feed_v,
        count => { map { $_ => scalar keys %{ $after->{sets}{$_}{elems} || {} } } qw(never_block never_block_v6 feedv4 feedv6) },
    };
    $self->_log(info => "firewall: rebuilt the table ($why)");
    return { ok => 1, replaced => $why, added => scalar(grep { $bans->{$_} - $now >= 10 } keys %$bans), removed => 0, feed_reloaded => 1 };
}

1;
