#!/usr/bin/perl
# The shared ban list (BadIPs::Engine::Store) against a REAL PostgreSQL:
# a private, throwaway cluster started in a temp directory (unix socket
# only, no TCP), with the fleet's role layout -- tables owned by
# badips_migrate, the daemon connecting as badips_runtime through default
# privileges. Skipped when no PostgreSQL server binaries are installed.
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../usr/local/lib/site_perl";
use lib "$FindBin::Bin/lib";
use TestPg;

my $pg = TestPg->start or plan skip_all => 'no PostgreSQL server binaries';
$pg->apply_schema;    # a second time: schema.sql must be idempotent
pass 'schema.sql applies as badips_migrate, twice';
my $su = $pg->su;

use BadIPs::Engine::Store;
my $db = $pg->db;
my $st = BadIPs::Engine::Store->new(db => $db, host => 'prod-homelab39');
my $now = 1_800_000_000;

my @dets = (
    { ip => '203.0.113.80', rule => 'postfix-auth', service => 'smtp', first => $now - 100, last => $now,
      expires => $now + 3600, hits => 5, lines => [ 'evidence 1', 'evidence 2' ] },
    { ip => '2001:db8::80', rule => 'dovecot-auth', service => 'imap', first => $now, last => $now,
      expires => $now + 3600, hits => 5, lines => ['v6 evidence'] },
);
is($st->push_detections(\@dets, $now), 2, 'the runtime login can write (default privileges cover the tables)') or diag $st->status;
my $a = $st->load_active($now);
is_deeply $a, { '203.0.113.80' => $now + 3600, '2001:db8::80' => $now + 3600 }, 'both bans active';

# a later, SHORTER ban from the same host does not cut the longer one
is $st->push_detections([ { %{ $dets[0] }, rule => 'postfix-auth-x', expires => $now + 60, last => $now + 10 } ], $now + 10), 1, 'second report';
is $st->load_active($now + 10)->{'203.0.113.80'}, $now + 3600, 'GREATEST keeps the longer ban';

# a longer ban extends it
$st->push_detections([ { %{ $dets[0] }, expires => $now + 86400, last => $now + 20 } ], $now + 20);
is $st->load_active($now + 20)->{'203.0.113.80'}, $now + 86400, 'a longer ban extends it';

# another host's report of the same address is its own row; active takes the max
my $st2 = BadIPs::Engine::Store->new(db => $db, host => 'prod-homelab00');
$st2->push_detections([ { %{ $dets[0] }, rule => 'nginx-probe', service => 'http', expires => $now + 604800 } ], $now);
is $st->load_active($now)->{'203.0.113.80'}, $now + 604800, 'any host\'s longest ban wins';

# expiry
ok !exists $st->load_active($now + 3601)->{'2001:db8::80'}, 'an expired ban is not active';

# unban: ends every host's ban on it and exempts it for a day
is $st->unban('203.0.113.80', by => 'gardner', reason => 'test', hours => 24, now => $now + 30), 2,
    'unban ended both hosts\' bans';
ok !exists $st->load_active($now + 31)->{'203.0.113.80'}, 'gone from the active list';
is $st->load_exemptions($now + 31)->{'203.0.113.80'}, $now + 30 + 86400, 'exempt for 24 hours';
$st->push_detections([ { %{ $dets[0] }, expires => $now + 9999, last => $now + 40 } ], $now + 40);
ok !exists $st->load_active($now + 41)->{'203.0.113.80'}, 'a fresh detection during the exemption stays inactive';
my $after = $now + 30 + 86400 + 1;
$st->push_detections([ { %{ $dets[0] }, expires => $after + 3600, last => $after } ], $after);
is $st->load_active($after)->{'203.0.113.80'}, $after + 3600, 'once the exemption runs out, a new detection is active again';

# a network exemption covers addresses inside it
$st->unban('2001:db8::80', by => 'x', now => $now);
my $su_dbh = $su;
$su_dbh->do("INSERT INTO badips.exemptions (ip, until_at, created_at) VALUES ('198.51.100.0/24', ?, ?)", undef, $now + 999, $now);
$st->push_detections([ { %{ $dets[0] }, ip => '198.51.100.9', expires => $now + 500 } ], $now);
ok !exists $st->load_active($now + 1)->{'198.51.100.9'}, 'a network exemption covers its addresses';

# manual ban clears an exemption
ok $st->ban('203.0.113.80', seconds => 600, reason => 'manual test', by => 'gardner', now => $now + 50), 'manual ban';
is $st->load_active($now + 51)->{'203.0.113.80'}, $after + 3600, 'manual ban lifts the exemption (and GREATEST keeps the longest end time)';

# list and why
my $l = $st->list($now + 51);
ok( (grep { $_->{ip} eq '203.0.113.80' && $_->{servers} =~ /prod-homelab39/ } @$l), 'list shows the ban and its hosts' );
my $w = $st->why('203.0.113.80', $now + 51);
ok @{ $w->{bans} } >= 2, 'why shows each host\'s row';
ok( (grep { ($_->{evidence} // '') =~ /evidence 1/ } @{ $w->{bans} }) || (grep { $_->{rule} eq 'manual' } @{ $w->{bans} }), 'why shows evidence' );
ok @{ $w->{exemptions} } >= 1, 'why shows the exemption history';

# --- the database going away is not fatal --------------------------------------
my $down = BadIPs::Engine::Store->new(db => { %$db, port => 1 }, host => 'h');
my $t0 = 2_000_000_000;
ok !defined $down->push_detections(\@dets, $t0), 'push fails cleanly when the database is unreachable';
like $down->status, qr/^down:/, 'status says why';
is $down->{retry_at}, $t0 + 5, 'next attempt after 5 s';
ok !defined $down->load_active($t0 + 1), 'no retry during the backoff';
$down->load_active($t0 + 6);
is $down->{retry_at}, $t0 + 6 + 10, 'backoff doubles';
$down->{db}{port} = $pg->{port};
ok defined $down->load_active($t0 + 100), 'and it reconnects on its own once the database is back';

done_testing;
