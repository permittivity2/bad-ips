#!/usr/bin/perl
# Country / network-owner lookup (BadIPs::Engine::Geo) from DB-IP Lite style
# CSVs, and its use against the shared list: the ip_geo table, the offenders
# view a read-only dashboard login is limited to.
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../usr/local/lib/site_perl", "$FindBin::Bin/lib";
use File::Temp qw(tempdir);
use BadIPs::Engine::Geo;

my $d = tempdir(CLEANUP => 1);
sub spit { my ($f, $c) = @_; open my $fh, '>', $f or die; print {$fh} $c; close $fh }

# a few thousand dummy rows so the "too small to be real" guard passes, and
# the interesting ones in the middle
my $country = join '', map { sprintf qq{"10.%d.%d.0","10.%d.%d.255","ZZ"\n}, int($_ / 256), $_ % 256, int($_ / 256), $_ % 256 } 0 .. 1200;
$country .= qq{"198.51.100.0","198.51.100.255","US"\n"203.0.113.0","203.0.113.255","DE"\n"2001:db8::","2001:db8:ffff:ffff:ffff:ffff:ffff:ffff","FR"\n};
my $asn = qq{"198.51.100.0","198.51.100.255","64500","Example Net, Inc."\n}
        . qq{"203.0.113.0","203.0.113.255","64501","Quote ""Co"" GmbH"\n}
        . qq{"2001:db8::","2001:db8:ffff:ffff:ffff:ffff:ffff:ffff","64502","Beispiel AG"\n};
spit("$d/country.csv", $country);
spit("$d/asn.csv", $asn);

my $geo = BadIPs::Engine::Geo->new(dir => "$d/out");
ok !$geo->available, 'nothing available before the data is built';
my $n = BadIPs::Engine::Geo::build(country => "$d/country.csv", asn => "$d/asn.csv", dir => "$d/out");
ok $geo->available, 'available after build';
ok $n->{country} > 1200 && $n->{asn} == 3, 'row counts reported';

is_deeply $geo->lookup('198.51.100.7'),  { country => 'US', asn => 64500, org => 'Example Net, Inc.' }, 'IPv4 country, ASN and owner (comma in the name)';
is_deeply $geo->lookup('203.0.113.255'), { country => 'DE', asn => 64501, org => 'Quote "Co" GmbH' }, 'last address of a range; quoted quotes';
is_deeply $geo->lookup('2001:db8::1234'), { country => 'FR', asn => 64502, org => 'Beispiel AG' }, 'IPv6';
is_deeply $geo->lookup('192.0.2.1'), { country => undef, asn => undef, org => undef }, 'not in the data: all undef (and that is an answer)';
is $geo->lookup('10.600.0.1')->{country}, undef, 'garbage in, undef out';
is $geo->lookup('10.3.9.9')->{country}, 'ZZ', 'a range from the middle of the file';
is $geo->lookup('1.2.3.4')->{country}, undef, 'before the first range';
is $geo->lookup('250.1.1.1')->{country}, undef, 'after the last range';

# too small to be a real download: refuse, keep what is installed
spit("$d/tiny.csv", qq{"1.0.0.0","1.0.0.255","AU"\n});
ok !eval { BadIPs::Engine::Geo::build(country => "$d/tiny.csv", asn => "$d/asn.csv", dir => "$d/out2"); 1 }, 'a tiny file is refused';
like $@, qr/refusing to install/, '...with a reason';
ok !-e "$d/out2/country4.bin", '...and nothing was installed';
is $geo->lookup('198.51.100.7')->{country}, 'US', 'the old data keeps working';

# --- against the shared list --------------------------------------------------------
require TestPg;
my $pg = TestPg->start or do { done_testing; exit };
use BadIPs::Engine::Store;
my $st  = BadIPs::Engine::Store->new(db => $pg->db, host => 'prod-homelab00');
my $now = 1_800_000_000;
$st->push_detections([ map { { ip => $_, rule => 'nginx-probe', service => 'http', first => $now, last => $now, expires => $now + 3600,
                               hits => 3, lines => ['GET /.env  user=someone@example.test'] } } qw(198.51.100.7 203.0.113.9) ], $now);
is_deeply [ sort @{ $st->unlocated($now, 10) } ], [qw(198.51.100.7 203.0.113.9)], 'both new bans need locating';
is $st->save_geo([ [ '198.51.100.7', 'US', 64500, 'Example Net, Inc.' ], [ '203.0.113.9', undef, undef, undef ] ], $now), 2, 'rows saved';
is_deeply $st->unlocated($now, 10), [], 'a lookup that found nothing is not asked again';

my $su = $pg->su;
my $rows = $su->selectall_arrayref('SELECT address, rule, country, network_owner FROM badips.offenders ORDER BY address');
is_deeply $rows, [ [ '198.51.100.7', 'nginx-probe', 'US', 'Example Net, Inc.' ], [ '203.0.113.9', 'nginx-probe', undef, undef ] ], 'the offenders view joins the bans with where they are from';
my @cols = map { $_->[0] } @{ $su->selectall_arrayref(q{SELECT column_name FROM information_schema.columns WHERE table_schema='badips' AND table_name='offenders'}) };
ok !(grep { /log|line|pattern/ } @cols), 'the view carries no log lines (they can hold user names)';
$su->do(q{INSERT INTO badips.exemptions (ip, until_at, reason, created_by, created_at) VALUES ('203.0.113.9', ?, 't', 't', ?)}, undef, $now + 99999999999, $now);
done_testing;
