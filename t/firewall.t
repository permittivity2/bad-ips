#!/usr/bin/perl
# The block role's reconcile loop (BadIPs::Engine::Firewall) against a fake
# kernel that applies sync requests the way nft does and reports `state`
# in nft's JSON shape.
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../usr/local/lib/site_perl";
use JSON ();

use BadIPs::Engine::Net;
use BadIPs::Engine::Firewall;

# --- a fake kernel ----------------------------------------------------------------
my $NOW = 1_800_000_000;
my $CLOCK = $NOW;    # the fake kernel's own clock, moved by rec()
my %K;               # exists, sets => { name => { addr => expires_at|undef } }, rules => [...]
my @calls;
my $fail_next_apply = 0;
my %TYPE = (badipv4 => ['ipv4_addr', 'timeout'], badipv6 => ['ipv6_addr', 'timeout'],
            feedv4 => ['ipv4_addr', 'interval'], feedv6 => ['ipv6_addr', 'interval'],
            never_block => ['ipv4_addr', 'interval'], never_block_v6 => ['ipv6_addr', 'interval']);

sub kernel_reset { %K = (exists => 0, sets => {}, rules => []) }
sub fam { $_[0] =~ /:/ ? 6 : 4 }

sub runner {
    my ($args, $stdin) = @_;
    push @calls, $args->[0];
    if ($args->[0] eq 'state') {
        return (1, '', 'Error: No such file or directory') unless $K{exists};
        my @o = ({ table => { family => 'inet', name => 'badips' } });
        for my $s (sort keys %{ $K{sets} }) {
            my ($type, $flag) = @{ $TYPE{$s} };
            my @el;
            for my $v (sort keys %{ $K{sets}{$s} }) {
                my $exp = $K{sets}{$s}{$v};
                if (defined $exp) { push @el, { elem => { val => $v, timeout => 1, expires => $exp - $CLOCK } } }
                elsif ($v =~ m{(.+)/(\d+)}) { push @el, { prefix => { addr => $1, len => $2 + 0 } } }
                else { push @el, $v }
            }
            push @o, { set => { family => 'inet', table => 'badips', name => $s, type => $type, flags => [$flag], (@el ? (elem => \@el) : ()) } };
        }
        push @o, { chain => { family => 'inet', table => 'badips', name => 'preroute_block', hook => 'prerouting', prio => -150, policy => 'accept' } };
        push @o, { rule => { family => 'inet', table => 'badips', chain => 'preroute_block', comment => $_ } } for @{ $K{rules} };
        return (0, JSON->new->encode({ nftables => \@o }), '');
    }
    if ($args->[0] eq 'sync') {
        my @l = grep { length } split /\n/, $stdin;
        my ($mode) = (shift @l) =~ /^mode (\w+)/;
        if ($mode eq 'apply' && $fail_next_apply) { $fail_next_apply = 0; return (1, '', 'Error: simulated failure') }
        if ($mode eq 'replace') {
            my (@if, $dns);
            %K = (exists => 1, sets => { map { $_ => {} } keys %TYPE }, rules => []);
            for (@l) {
                my ($c, $a, $b) = split ' ';
                if    ($c eq 'iface') { push @if, $a }
                elsif ($c eq 'dns_accept') { $dns = $a }
                elsif ($c eq 'never') { $K{sets}{ fam($a) == 4 ? 'never_block' : 'never_block_v6' }{$a} = undef }
                elsif ($c eq 'feed')  { $K{sets}{ fam($a) == 4 ? 'feedv4' : 'feedv6' }{$a} = undef }
                elsif ($c eq 'ban')   { $K{sets}{ fam($a) == 4 ? 'badipv4' : 'badipv6' }{$a} = $CLOCK + $b }
            }
            $K{rules} = [ (@if ? 'badips:iface' : ()), 'badips:never4', 'badips:never6', ($dns ? 'badips:dns' : ()),
                          qw(badips:ban4 badips:ban6 badips:feed4 badips:feed6) ];
            return (0, '', '');
        }
        for (@l) {
            my ($c, $a, $b) = split ' ';
            if    ($c eq 'feedreset') { $K{sets}{feedv4} = {}; $K{sets}{feedv6} = {} }
            elsif ($c eq 'feed')  { $K{sets}{ fam($a) == 4 ? 'feedv4' : 'feedv6' }{$a} = undef }
            elsif ($c eq 'unban') { delete $K{sets}{ fam($a) == 4 ? 'badipv4' : 'badipv6' }{$a} }
            elsif ($c eq 'ban')   { $K{sets}{ fam($a) == 4 ? 'badipv4' : 'badipv6' }{$a} = $CLOCK + $b }
        }
        return (0, '', '');
    }
    return (2, '', 'unknown');
}

# What `systemctl reload nftables` leaves: the persistent file recreates the
# table with its never-block list, but bans and feed ranges are gone.
sub simulate_reload {
    $K{sets}{$_} = {} for qw(badipv4 badipv6 feedv4 feedv6);
}

kernel_reset();
my $never = BadIPs::Engine::NeverBlock->new('192.0.2.64/29', '198.51.100.45/32', '2001:db8:5400:2e7f::/64', '10.50.0.0/16');
my $fw = BadIPs::Engine::Firewall->new(runner => \&runner, ifaces => [qw(eth6 eth7)], dns_accept => 1, never => $never);

my %bans = ('203.0.113.7' => $NOW + 3600, '2001:db8::7' => $NOW + 600);
my @feed = ('1.10.16.0/20', '1.10.16.0/24', '2001:678:254::/48');

# --- first reconcile builds the table --------------------------------------------
my $r = do { $CLOCK = $NOW; $fw->reconcile(bans => \%bans, feed => \@feed, now => $NOW) };
ok $r->{ok}, 'first reconcile ok';
like $r->{replaced}, qr/table missing/, 'a missing table is rebuilt';
ok exists $K{sets}{badipv4}{'203.0.113.7'}, 'v4 ban in place';
ok exists $K{sets}{badipv6}{'2001:db8::7'}, 'v6 ban in place';
ok exists $K{sets}{never_block}{'192.0.2.64/29'}, 'house in never-block';
ok exists $K{sets}{never_block}{'198.51.100.45'}, 'offsite in never-block';
ok !exists $K{sets}{never_block}{'10.50.0.0/16'}, 'an entry inside the floor\'s 10/8 is folded away (no overlapping elements)';
is_deeply [ sort keys %{ $K{sets}{feedv4} } ], ['1.10.16.0/20'], 'a feed range inside another is folded away';
is_deeply $K{rules}, [qw(badips:iface badips:never4 badips:never6 badips:dns badips:ban4 badips:ban6 badips:feed4 badips:feed6)], 'rules';

# --- nothing to do ------------------------------------------------------------------
@calls = ();
$r = do { $CLOCK = $NOW + 30; $fw->reconcile(bans => \%bans, feed => \@feed, now => $NOW + 30) };
ok $r->{ok} && !$r->{replaced} && !$r->{added} && !$r->{removed} && !$r->{feed_reloaded}, 'steady state: no change';
is_deeply \@calls, ['state'], 'steady state costs one read and no write';

# --- new ban, ended ban ---------------------------------------------------------------
my %b2 = (%bans, '198.51.100.20' => $NOW + 7200);
delete $b2{'2001:db8::7'};
$r = do { $CLOCK = $NOW + 60; $fw->reconcile(bans => \%b2, feed => \@feed, now => $NOW + 60) };
is $r->{added}, 1, 'a new ban is added';
is $r->{removed}, 1, 'an ended/unbanned address is removed';
ok exists $K{sets}{badipv4}{'198.51.100.20'} && !exists $K{sets}{badipv6}{'2001:db8::7'}, 'kernel matches';

# --- an nftables reload ---------------------------------------------------------------
simulate_reload();
$r = do { $CLOCK = $NOW + 90; $fw->reconcile(bans => \%b2, feed => \@feed, now => $NOW + 90) };
ok !$r->{replaced}, 'after a reload the table (from the persistent file) is kept...';
is $r->{added}, 2, '...and every ban is put back';
ok $r->{feed_reloaded}, '...and the feed ranges are reloaded';
ok exists $K{sets}{feedv4}{'1.10.16.0/20'}, 'feed back';

# --- a flush ruleset (no table at all) --------------------------------------------------
kernel_reset();
$r = do { $CLOCK = $NOW + 120; $fw->reconcile(bans => \%b2, feed => \@feed, now => $NOW + 120) };
like $r->{replaced}, qr/table missing/, 'flush ruleset: the whole table is rebuilt';
ok exists $K{sets}{badipv4}{'198.51.100.20'}, 'bans back';

# --- never-block emptied (someone ran the 3.x installer, or flushed the set) -----------
$K{sets}{never_block} = {};
$r = do { $CLOCK = $NOW + 150; $fw->reconcile(bans => \%b2, feed => \@feed, now => $NOW + 150) };
like $r->{replaced}, qr/never-block entries missing/, 'an emptied never-block set forces a rebuild';
ok exists $K{sets}{never_block}{'192.0.2.64/29'}, 'house back in never-block';

# --- structure differs ------------------------------------------------------------------
push @{ $K{rules} }, 'someone:else';
$r = do { $CLOCK = $NOW + 180; $fw->reconcile(bans => \%b2, feed => \@feed, now => $NOW + 180) };
like $r->{replaced}, qr/structure differs/, 'an unexpected rule forces a rebuild';

# --- settings change ----------------------------------------------------------------------
my $fw2 = BadIPs::Engine::Firewall->new(runner => \&runner, ifaces => ['eth6'], dns_accept => 1, never => $never);
$r = do { $CLOCK = $NOW + 200; $fw2->reconcile(bans => \%b2, feed => \@feed, now => $NOW + 200) };
ok $r->{replaced}, 'a different interface list rebuilds the table';
ok do { $CLOCK = $NOW + 230; $fw2->reconcile(bans => \%b2, feed => \@feed, now => $NOW + 230) }->{ok}, 'and then settles';

# --- extension --------------------------------------------------------------------------
my %b3 = %b2;
$b3{'203.0.113.7'} = $NOW + 86400;    # re-banned for longer than the kernel will hold it
$r = do { $CLOCK = $NOW + 260; $fw2->reconcile(bans => \%b3, feed => \@feed, now => $NOW + 260) };
is $r->{extended}, 1, 'a ban that the kernel would drop too early is re-added longer';
is $K{sets}{badipv4}{'203.0.113.7'}, $NOW + 86400, 'kernel now holds the longer ban';

# a ban longer than the 30-day timeout cap does not churn every cycle
my %b4 = (%b3, '203.0.113.8' => $NOW + 90 * 86400);
do { $CLOCK = $NOW + 300; $fw2->reconcile(bans => \%b4, feed => \@feed, now => $NOW + 300) };
$r = do { $CLOCK = $NOW + 330; $fw2->reconcile(bans => \%b4, feed => \@feed, now => $NOW + 330) };
ok !$r->{extended} && !$r->{added}, 'a 90-day ban sits at the 30-day cap without churning';

# --- an apply that fails falls back to a rebuild ------------------------------------------
$fail_next_apply = 1;
my %b5 = (%b4, '198.51.100.99' => $NOW + 999);
$r = do { $CLOCK = $NOW + 360; $fw2->reconcile(bans => \%b5, feed => \@feed, now => $NOW + 360) };
like $r->{replaced}, qr/apply failed/, 'a failed apply falls back to a full rebuild';
ok exists $K{sets}{badipv4}{'198.51.100.99'}, 'and the change still lands';

# --- the helper itself failing -------------------------------------------------------------
my $broken = BadIPs::Engine::Firewall->new(runner => sub { (1, '', 'sudo: a password is required') }, never => $never);
$r = $broken->reconcile(bans => \%b5, feed => [], now => $NOW);
ok !$r->{ok}, 'a broken helper is reported, not hidden';
like $r->{error}, qr/password is required/, 'with its message';

# --- minimize -----------------------------------------------------------------------------
is_deeply [ BadIPs::Engine::Firewall::minimize('10.0.0.0/8', '10.50.0.0/16', '10.0.0.0/8', '224.0.0.0/4', '240.0.0.0/4', '::/0', 'fe80::/10') ],
    [ '10.0.0.0/8', '224.0.0.0/4', '240.0.0.0/4', '::/0' ], 'contained and duplicate entries dropped; adjacent ones kept';

done_testing;
