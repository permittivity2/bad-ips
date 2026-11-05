package FakeKernel;

# A stand-in for `bad_ips_nft` + the kernel's `inet badips` table, for
# tests of the reconcile logic. It applies sync requests the way nft does
# and answers `state` in nft's JSON shape, with element expiries counted
# down from its own clock ($k->{clock}, which tests move).
#
#   my $k = FakeKernel->new;
#   my $fw = BadIPs::Engine::Firewall->new(runner => $k->runner, ...);
#   $k->reload;      # what `systemctl reload nftables` leaves behind
#   $k->flush;       # what `nft flush ruleset` leaves behind

use strict;
use warnings;
use JSON ();

my %TYPE = (badipv4 => ['ipv4_addr', 'timeout'], badipv6 => ['ipv6_addr', 'timeout'],
            feedv4 => ['ipv4_addr', 'interval'], feedv6 => ['ipv6_addr', 'interval'],
            never_block => ['ipv4_addr', 'interval'], never_block_v6 => ['ipv6_addr', 'interval']);

sub new { my ($class, %a) = @_; my $s = bless { clock => $a{clock} // time, calls => [], fail_apply => 0 }, $class; $s->flush; $s }
sub flush { my ($s) = @_; @{$s}{qw(exists sets rules)} = (0, {}, []) }
sub reload { my ($s) = @_; $s->{sets}{$_} = {} for qw(badipv4 badipv6 feedv4 feedv6) }
sub fam { $_[0] =~ /:/ ? 6 : 4 }

sub has {    # $k->has('badipv4', '203.0.113.7')
    my ($s, $set, $v) = @_;
    my $e = $s->{sets}{$set} or return 0;
    return 0 unless exists $e->{$v};
    return !defined $e->{$v} || $e->{$v} > $s->{clock};
}

sub runner {
    my ($s) = @_;
    return sub { $s->call(@_) };
}

sub call {
    my ($s, $args, $stdin) = @_;
    push @{ $s->{calls} }, $args->[0];
    # elements whose timeout ran out are gone, as in the kernel
    for my $set (qw(badipv4 badipv6)) {
        my $e = $s->{sets}{$set} or next;
        delete @{$e}{ grep { defined $e->{$_} && $e->{$_} <= $s->{clock} } keys %$e };
    }
    if ($args->[0] eq 'state') {
        return (1, '', 'Error: No such file or directory') unless $s->{exists};
        my @o = ({ table => { family => 'inet', name => 'badips' } });
        for my $set (sort keys %{ $s->{sets} }) {
            my ($type, $flag) = @{ $TYPE{$set} };
            my @el;
            for my $v (sort keys %{ $s->{sets}{$set} }) {
                my $exp = $s->{sets}{$set}{$v};
                if (defined $exp)            { push @el, { elem => { val => $v, timeout => 1, expires => $exp - $s->{clock},
                                                                     counter => { packets => $s->{element_packets}{$set}{$v} // 0, bytes => 0 } } } }
                elsif ($v =~ m{(.+)/(\d+)}) { push @el, { prefix => { addr => $1, len => $2 + 0 } } }
                else                         { push @el, $v }
            }
            push @o, { set => { family => 'inet', table => 'badips', name => $set, type => $type, flags => [$flag], (@el ? (elem => \@el) : ()),
                              ($set =~ /\Abadipv[46]\z/ ? (stmt => [ { counter => undef } ]) : ()) } };
        }
        push @o, { chain => { family => 'inet', table => 'badips', name => 'preroute_block', hook => 'prerouting', prio => -150, policy => 'accept' } };
        push @o, { rule => { family => 'inet', table => 'badips', chain => 'preroute_block', comment => $_,
            expr => [ { counter => { packets => $s->{rule_packets}{$_} // 0, bytes => 0 } } ] } } for @{ $s->{rules} };
        return (0, JSON->new->encode({ nftables => \@o }), '');
    }
    if ($args->[0] eq 'remove') { $s->flush; return (0, '', '') }
    if ($args->[0] eq 'sync') {
        my @l = grep { length } split /\n/, $stdin;
        my ($mode) = (shift @l) =~ /^mode (\w+)/;
        if ($mode eq 'apply' && $s->{fail_apply}) { $s->{fail_apply} = 0; return (1, '', 'Error: simulated failure') }
        if ($mode eq 'replace') {
            my (@if, $dns);
            @{$s}{qw(exists sets rules)} = (1, { map { $_ => {} } keys %TYPE }, []);
            for (@l) {
                my ($c, $a, $b) = split ' ';
                if    ($c eq 'iface')      { push @if, $a }
                elsif ($c eq 'dns_accept') { $dns = $a }
                elsif ($c eq 'never')      { $s->{sets}{ fam($a) == 4 ? 'never_block' : 'never_block_v6' }{$a} = undef }
                elsif ($c eq 'feed')       { $s->{sets}{ fam($a) == 4 ? 'feedv4' : 'feedv6' }{$a} = undef }
                elsif ($c eq 'ban')        { $s->{sets}{ fam($a) == 4 ? 'badipv4' : 'badipv6' }{$a} = $s->{clock} + $b }
            }
            $s->{rules} = [ (@if ? 'badips:iface' : ()), 'badips:never4', 'badips:never6', ($dns ? 'badips:dns' : ()), 'badips:knock_all:ssh',
                            (map { my $l = $_; map { "badips:knock:$l:$_" } @BadIPs::Engine::Firewall::KNOCK_GROUPS } @BadIPs::Engine::Firewall::KNOCK_LISTS),
                            qw(badips:ban4 badips:ban6 badips:feed4 badips:feed6) ];
            return (0, '', '');
        }
        for (@l) {
            my ($c, $a, $b) = split ' ';
            if    ($c eq 'feedreset') { $s->{sets}{feedv4} = {}; $s->{sets}{feedv6} = {} }
            elsif ($c eq 'feed')      { $s->{sets}{ fam($a) == 4 ? 'feedv4' : 'feedv6' }{$a} = undef }
            elsif ($c eq 'unban')     { delete $s->{sets}{ fam($a) == 4 ? 'badipv4' : 'badipv6' }{$a} }
            elsif ($c eq 'ban')       { $s->{sets}{ fam($a) == 4 ? 'badipv4' : 'badipv6' }{$a} = $s->{clock} + $b }
        }
        return (0, '', '');
    }
    return (2, '', 'unknown');
}

1;
