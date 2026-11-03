#!/usr/bin/perl
# Address parsing and the never-block list (BadIPs::Engine::Net).
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../usr/local/lib/site_perl";

use BadIPs::Engine::Net qw(parse_cidr parse_addr overlaps normalize_addr);

# --- parsing ----------------------------------------------------------------
is parse_cidr('10.1.2.3/8')->{text}, '10.0.0.0/8', 'host bits cleared';
is parse_cidr('192.0.2.7')->{text}, '192.0.2.7', 'bare v4 address keeps its text';
ok parse_cidr('192.0.2.7')->{single}, 'bare address is single';
is parse_cidr('192.0.2.7/32')->{text}, '192.0.2.7', 'full-length prefix prints as a bare address';
is parse_cidr('2001:DB8:0:0::1')->{text}, '2001:db8::1', 'v6 normalised to lower-case compressed form';
is parse_cidr('2001:db8:5400:2e7f:1:2:3:4/64')->{text}, '2001:db8:5400:2e7f::/64', 'v6 host bits cleared';
is normalize_addr('2001:0db8::0001'), '2001:db8::1', 'normalize_addr';
ok !defined parse_addr('10.0.0.0/8'), 'parse_addr refuses a network';

for my $bad ('256.1.1.1', '01.2.3.4', '1.2.3', '1.2.3.4/33', '::1/129', 'abc', '', '1.2.3.4 ', '1.2.3.4/8/8', '1:2:3:4:5:6:7:8:9') {
    my $p = parse_cidr($bad);
    # a trailing space is trimmed and so is valid; everything else must fail
    if ($bad eq '1.2.3.4 ') { ok $p, "trailing whitespace trimmed ('$bad')"; next }
    ok !defined $p, "invalid input refused: '$bad'";
}

# --- overlap ----------------------------------------------------------------
ok overlaps(parse_cidr('192.0.0.0/16'), parse_cidr('192.0.2.64/29')), 'a wider block overlaps a narrower one inside it';
ok overlaps(parse_cidr('192.0.2.65'), parse_cidr('192.0.2.64/29')), 'an address inside a block overlaps it';
ok !overlaps(parse_cidr('192.0.2.72'), parse_cidr('192.0.2.64/29')), 'the next address after a /29 does not';
ok !overlaps(parse_cidr('10.0.0.0/8'), parse_cidr('::/0')), 'different families never overlap';

# --- never-block ------------------------------------------------------------
my $nb = BadIPs::Engine::NeverBlock->new(
    '192.0.2.64/29', '198.51.100.45/32', '2001:db8:5400:2e7f::/64',
);
is_deeply [ $nb->errors ], [], 'no errors for a valid list';

for my $h (64 .. 71) {
    ok $nb->conflict("192.0.2.$h"), "house address 192.0.2.$h is never blocked";
}
ok $nb->conflict('198.51.100.45'), 'offsite v4 is never blocked';
ok !$nb->conflict('198.51.100.46'), 'its neighbour is not protected (we never-block the /32, not the /23)';
ok $nb->conflict('2001:db8:5400:2e7f:1:2:3:4'), 'offsite v6 is never blocked';
ok $nb->conflict('2001:db8:5400:2e7f::dead'), 'anything in offsite\'s /64 is never blocked';
ok !$nb->conflict('2001:db8:5400:2e80::1'), 'the next /64 is not';

is $nb->conflict('192.0.0.0/16'), '192.0.2.64/29', 'a range CONTAINING the house is refused';
ok $nb->conflict('0.0.0.0/0'), 'everything-v4 is refused';
ok $nb->conflict('::/0'), 'everything-v6 is refused';

# the floor
for my $a (qw(10.50.2.144 192.168.1.223 172.16.5.5 127.0.0.1 169.254.1.1 224.0.0.1 255.255.255.255 0.0.0.0
              ::1 fe80::1 fd00::1 ff02::1)) {
    ok $nb->conflict($a), "floor: $a is never blocked";
}
ok !$nb->conflict('203.0.113.7'), 'TEST-NET-3 is blockable (the verification test bans 203.0.113.7)';
ok !$nb->conflict('196.251.121.113'), 'an ordinary internet address is blockable';
ok $nb->conflict('not-an-address'), 'garbage is treated as never-block, so it is never blocked';

my $bad = BadIPs::Engine::NeverBlock->new('192.0.2.64/29', '192.0.2.300');
is scalar($bad->errors), 1, 'an invalid entry is reported, not silently dropped';

my @v4 = $nb->cidrs(4);
ok( (grep { $_ eq '192.0.2.64/29' } @v4), 'cidrs(4) lists the house' );
ok( !(grep { /:/ } @v4), 'cidrs(4) has no v6 entries' );

done_testing;
