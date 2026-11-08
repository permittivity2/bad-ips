#!/usr/bin/perl
# bad_ips --test-config (BadIPs::Engine::CLI::test_config). What it prints is
# what an installer checks a node by, so where each deciding setting came
# from and whether the shared list is reachable are part of its contract.
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../usr/local/lib/site_perl";
use lib "$FindBin::Bin/lib";
use File::Temp qw(tempdir);
use TestPg;
use BadIPs::Engine::CLI;

sub conf_tree {
    my (%files) = @_;
    my $dir = tempdir(CLEANUP => 1);
    mkdir "$dir/d";
    for my $f (keys %files) { open my $fh, '>', "$dir/$f" or die; print {$fh} $files{$f}; close $fh }
    return (conf_main => "$dir/badips.conf", conf_dir => "$dir/d");
}

sub run_tc {
    my (%a) = @_;
    open my $fh, '>', \my $out or die;
    my $old = select $fh;
    my $rc = BadIPs::Engine::CLI::test_config(%a);
    select $old;
    close $fh;
    return ($rc, $out);
}

# a command (unban, ban, list, why): its exit code and what it printed
sub run_cmd {
    my ($argv, %a) = @_;
    open my $fh, '>', \my $out or die;
    my $old = select $fh;
    my $rc = BadIPs::Engine::CLI::main(%a, argv => $argv);
    select $old;
    close $fh;
    return ($rc, $out);
}

my $ROLE  = "[global]\nrole = report\n";
my $FLEET = "[global]\nnever_block_cidrs = 203.0.113.0/29\n";
my $DB96  = "[global]\ndb_host = 192.0.2.1\ndb_port = 6432\ndb_name = homelab\ndb_user = badips_runtime\ndb_password = x\ndb_schema = badips\n";

# --- the database unreachable: said plainly, and not a configuration error ----
my %t = conf_tree('d/94-role.conf' => $ROLE, 'd/95-fleet.conf' => $FLEET, 'd/96-fleet-db.conf' => $DB96);
my ($rc, $out) = run_tc(%t, connect => sub { die "connection refused\n" });
is $rc, 0, 'an unreachable database is not a configuration error';
like $out, qr{^role:\s+report  \(from \S+/d/94-role\.conf\)$}m, 'the role line names its file';
like $out, qr{^never-block:.*203\.0\.113\.0/29.*  \(from \S+/d/95-fleet\.conf\)$}m, 'the never-block line names its file';
like $out, qr{^database:\s+192\.0\.2\.1:6432/homelab as badips_runtime, schema badips  \(from \S+/d/96-fleet-db\.conf\)$}m,
    'the database line names its file';
like $out, qr{^\s+NOT reachable: down: connection refused$}m, 'unreachable, with the reason';
like $out, qr{^configuration OK$}m, 'configuration OK';

# --- the leftover: refused, exit 1, both files named, nothing tried -------------
%t = conf_tree('d/94-role.conf' => $ROLE, 'd/95-fleet.conf' => $FLEET, 'd/96-fleet-db.conf' => $DB96,
    'd/database.conf' => "[global]\ndb_host = 10.10.0.116\ndb_port = 5432\ndb_name = bad_ips\ndb_user = bad_ips\ndb_password = oldsecret\n");
my $tried = 0;
($rc, $out) = run_tc(%t, connect => sub { $tried++; die "should not be tried\n" });
is $rc, 1, 'a leftover database file: exit 1';
like $out, qr{^ERROR:\s+the database settings in \[global\] come from more than one file: \S+/d/96-fleet-db\.conf .*\S+/d/database\.conf}m,
    'the ERROR names both files';
like $out, qr{daemon would refuse to start}, '...and says the daemon would refuse';
is $tried, 0, 'no connection is attempted with a refused configuration';
unlike $out, qr/oldsecret/, 'no password printed';

# --- reachable: against a real, private PostgreSQL ------------------------------
SKIP: {
    my $pg = TestPg->start or skip 'no PostgreSQL server binaries', 12;
    %t = conf_tree('d/94-role.conf' => $ROLE, 'd/95-fleet.conf' => $FLEET, 'd/96-fleet-db.conf' => "[global]\n" . $pg->db_conf);
    ($rc, $out) = run_tc(%t);
    is $rc, 0, 'a reachable database: exit 0';
    like $out, qr{^\s+reachable; 0 active bans$}m, 'reachable, with the active count';
    like $out, qr{^database:\s+\S+:\d+/postgres as badips_runtime, schema badips  \(from \S+/d/96-fleet-db\.conf\)$}m,
        'the database line, from the real file';

    # --- list: the last line counts ALL active bans, not the rows shown ----------
    ($rc, $out) = run_cmd(['list'], %t);
    is $rc, 0, 'list with nothing banned: exit 0';
    like $out, qr{^0 active bans$}m, '...says 0 active bans';
    # (203.0.113.0/29 is this test's never-block list, so these start at .17)
    ($rc, $out) = run_cmd([ 'ban', '203.0.113.17', '--for', '10m', '--reason', 'test' ], %t);
    is $rc, 0, 'ban';
    run_cmd([ 'ban', '203.0.113.18', '--for', '10m' ], %t);
    run_cmd([ 'ban', '203.0.113.19', '--for', '10m' ], %t);
    ($rc, $out) = run_cmd(['list'], %t);
    like $out, qr{^3 active bans$}m, 'three bans, no limit: "3 active bans"';
    ($rc, $out) = run_cmd([ 'list', '--limit', '2' ], %t);
    is $rc, 0, 'list --limit 2: exit 0';
    is scalar(() = $out =~ /^203\.0\.113\.\d+ /mg), 2, '...shows two rows';
    like $out, qr{^showing 2 of 3 active bans$}m, '...and says "showing 2 of 3 active bans", not "2 active bans"';
    ($rc, $out) = run_cmd([ 'list', '--limit', '5' ], %t);
    like $out, qr{^3 active bans$}m, 'a limit above the count: the plain count';
    ($rc, $out) = run_cmd([ 'list', '--limit', '1' ], %t);
    like $out, qr{^showing 1 of 3 active bans$}m, 'one row: "showing 1 of 3", not "1 active ban"';
}

done_testing;
