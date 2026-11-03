#!/usr/bin/perl
# Role-mode configuration (BadIPs::Engine::Config).
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../usr/local/lib/site_perl";
use File::Temp qw(tempdir);
use File::Copy qw(copy);

use BadIPs::Engine::Config;

my $repo = "$FindBin::Bin/..";

sub tree {
    my (%files) = @_;
    my $dir = tempdir(CLEANUP => 1);
    mkdir "$dir/d";
    # the package's shipped files, as installed
    copy("$repo/usr/local/etc/badips.d/$_", "$dir/d/$_") or die "$_: $!"
        for qw(10-sshd.conf 20-postfix.conf 30-dovecot.conf 40-nginx.conf 50-apache.conf 60-rules.conf 70-bind.conf 80-publicblocklists.conf);
    for my $f (keys %files) {
        open my $fh, '>', "$dir/$f" or die; print {$fh} $files{$f}; close $fh;
    }
    return (conf_main => "$dir/badips.conf", conf_dir => "$dir/d", host => 'testhost');
}

my $DB = "db_host = 10.50.2.131\ndb_port = 6432\ndb_name = homelab\ndb_user = badips_runtime\ndb_password = x\ndb_schema = badips\n";

# --- no role: legacy mode ----------------------------------------------------
is BadIPs::Engine::Config::role_from_files(tree()), undef, 'no role anywhere -> legacy mode';
is BadIPs::Engine::Config::role_from_files(tree('d/94-role.conf' => "[global]\nrole = report\n")), 'report',
    'role read from badips.d';

# --- a typical report host ----------------------------------------------------
my ($s, $err, $notes) = BadIPs::Engine::Config::load(tree(
    'd/94-role.conf'  => "[global]\nrole = report\n",
    'd/95-fleet.conf' => "[global]\nnever_block_cidrs = 192.0.2.64/29, 198.51.100.45/32, 2001:db8:5400:2e7f::/64\n",
    'd/96-db.conf'    => "[global]\n$DB",
));
is_deeply $err, [], 'report host config is valid';
is $s->{role}, 'report', 'role';
is $s->{db}{schema}, 'badips', 'db schema';
is $s->{db}{port}, 6432, 'db port';
ok $s->{never}->conflict('192.0.2.65'), 'house is never-blocked';
ok $s->{never}->conflict('2001:db8:5400:2e7f::1'), 'offsite v6 is never-blocked';
ok $s->{never}->conflict('10.50.2.144'), 'the floor is always there';
is_deeply [ sort map { $_->{name} } @{ $s->{rules} } ],
    [qw(dovecot-auth nginx-catchall-flood nginx-probe postfix-abuse postfix-auth postfix-auth-slow)],
    'only the [rule:*] sections run -- none of the legacy detectors';
like "@$notes", qr/legacy sections ignored in role mode: .*detector:nginx/, 'ignored legacy sections are listed';
is scalar @{ $s->{feeds} }, 1, 'the shipped Spamhaus feed is loaded';

# --- a later file switches a shipped rule off, or replaces it whole ----------
($s, $err) = BadIPs::Engine::Config::load(tree(
    'd/94-role.conf' => "[global]\nrole = report\n$DB",
    'd/95-site.conf' => "[rule:nginx-probe]\nactive = 0\n\n[rule:postfix-auth]\nsource = /var/log/other.log\nmatch = ^(?<ip>\\S+) bad\ncount = 2\nwindow = 60\nban = 120\n",
));
is_deeply $err, [], 'override config is valid';
my %r = map { $_->{name} => $_ } @{ $s->{rules} };
ok !$r{'nginx-probe'}, 'a later file switched a shipped rule off (3.x could not)';
is $r{'postfix-auth'}{count}, 2, 'a later file replaced a shipped rule whole';
is_deeply $r{'postfix-auth'}{files}, ['/var/log/other.log'], '...including its source';

# --- host sections win over global regardless of file order ------------------
($s, $err) = BadIPs::Engine::Config::load(tree(
    'd/10-a.conf'   => "[host:testhost]\nrole = block\nblock_interfaces = eth6, eth7\n",
    'd/94-role.conf' => "[global]\nrole = report\n$DB",
));
is $s->{role}, 'block', '[host:<me>] beats a later [global]';
is_deeply $s->{block_interfaces}, [qw(eth6 eth7)], 'block interfaces';

# --- refusals -------------------------------------------------------------------
sub errors_for { my ($e) = (BadIPs::Engine::Config::load(tree(@_)))[1]; return "@$e" }
like errors_for('d/94-role.conf' => "[global]\nrole = enforce\n"), qr/role must be one of/, 'unknown role refused';
like errors_for('d/94-role.conf' => "[global]\nrole = report\n"), qr/role = report needs the database/, 'report without a database refused';
like errors_for('d/94-role.conf' => "[global]\nrole = block\ndb_host = x\n"), qr/database settings incomplete: missing db_name, db_user, db_password/, 'partial database settings refused';
like errors_for('d/94-role.conf' => "[global]\nrole = block\nnever_block_cidrs = 192.0.2.64/29, 192.0.2.999\n"), qr/invalid never-block entry/, 'a bad never-block entry refuses the whole config';
like errors_for('d/94-role.conf' => "[global]\nrole = block\nblock_interfaces = eth6;rm\n"), qr/not an interface name/, 'a bad interface name refused';
like errors_for('d/94-role.conf' => "[global]\nrole = block\n[rule:bad]\nsource = /x\nmatch = ^(\\S+)\ncount = 1\nwindow = 1\nban = 60\n"), qr/rule bad .*\(\?<ip>/, 'a broken rule refuses the whole config';
like errors_for('d/94-role.conf' => "[global]\nrole = block\ndry_run = yes\n"), qr/dry_run must be 0 or 1/, 'a bad boolean refused';
like errors_for('d/94-role.conf' => "[global]\nrole = block\n[mystery]\nx = 1\n"), qr/unknown section \[mystery\]/, 'an unknown section refused';
like errors_for('d/94-role.conf' => "[global]\nrole = block\n[feed:x]\nurls = ftp://example.com/x\n"), qr/not an http\(s\) URL/, 'a bad feed URL refused';

# --- block role without a database is allowed (local detections only) --------
($s, $err) = BadIPs::Engine::Config::load(tree('d/94-role.conf' => "[global]\nrole = block\ndry_run = 1\n"));
is_deeply $err, [], 'block without a database is valid';
ok !$s->{db}, 'no database';
is $s->{dry_run}, 1, 'watch mode';

# --- one file each for what matters (found 2026-11-02) -------------------------
# The fleet case exactly: the fleet's three files, plus what a purged 3.x
# install left in the base images -- a generated badips.conf and a generated
# badips.d/database.conf pointing at a dead database. "database.conf" sorts
# after "96-fleet-db.conf", so under plain "a later file wins" the dead one won.
my $OLD_DB = "# Bad IPs Database Configuration\n# This file is automatically generated during installation\n\n[global]\n"
    . "db_host = 10.10.0.116\ndb_port = 5432\ndb_name = bad_ips\ndb_user = bad_ips\ndb_password = oldsecret\ndb_ssl_mode = disable\n";
my %FLEET = (
    'd/94-role.conf'     => "[global]\nrole = block\ndry_run = 1\nblock_interfaces = eth6, eth7\n",
    'd/95-fleet.conf'    => "[global]\nnever_block_cidrs = 192.0.2.64/29, 198.51.100.45/32, 2001:db8:5400:2e7f::/64\n",
    'd/96-fleet-db.conf' => "[global]\n$DB",
);
($s, $err) = BadIPs::Engine::Config::load(tree(%FLEET));
is_deeply $err, [], 'the fleet files alone are valid';
like $s->{from}{role}, qr{/d/94-role\.conf\z}, 'the role is known to come from 94-role.conf';
like $s->{from}{never_block_cidrs}, qr{/d/95-fleet\.conf\z}, 'the never-block list is known to come from 95-fleet.conf';
like $s->{db}{from}, qr{/d/96-fleet-db\.conf\z}, 'the database is known to come from 96-fleet-db.conf';

my $e = errors_for(%FLEET, 'd/database.conf' => $OLD_DB);
like $e, qr/the database settings in \[global\] come from more than one file/, 'a leftover database.conf is refused, not silently preferred';
like $e, qr{/d/96-fleet-db\.conf \(db_host=10\.50\.2\.131,.*/d/database\.conf \(db_host=10\.10\.0\.116,}, '...naming both files and both hosts';
unlike $e, qr/oldsecret|db_password=/, '...without printing either password';

like errors_for(%FLEET, 'badips.conf' => "[global]\nnever_block_cidrs = 10.0.0.0/8,192.0.2.69\n"),
    qr{never_block_cidrs is set differently by more than one file in \[global\]: \S*/badips\.conf says '10\.0\.0\.0/8,192\.0\.2\.69'; \S*/d/95-fleet\.conf says},
    'a leftover badips.conf with its own never-block list is refused';
like errors_for(%FLEET, 'd/99-local.conf' => "[global]\nrole = report\n"), qr/role is set differently/, 'two different roles refused';
like errors_for(%FLEET, 'd/99-local.conf' => "[global]\ndry_run = 0\n"), qr/dry_run is set differently/, 'watch mode switched off by another file is refused';
like errors_for(%FLEET, 'd/99-local.conf' => "[global]\nblock_interfaces = eth0\n"), qr/block_interfaces is set differently/, 'other interfaces from another file refused';
like errors_for(%FLEET, 'd/99-local.conf' => "[global]\ndb_ssl_mode = disable\n"), qr/database settings in \[global\] come from more than one file/,
    'even ONE database setting from a second file is refused (never mixed)';

($s, $err) = BadIPs::Engine::Config::load(tree(%FLEET, 'd/99-same.conf' => "[global]\nrole = block\nblock_interfaces = eth6,eth7\n"));
is_deeply $err, [], 'the same value in two files is not a conflict (spacing around commas ignored)';

($s, $err) = BadIPs::Engine::Config::load(tree('d/94-role.conf' => "[global]\nrole = report\n", 'd/database.conf' => "[global]\n$DB"));
is_deeply $err, [], 'database settings in database.conf alone are fine (the standalone layout)';
like $s->{db}{from}, qr{/d/database\.conf\z}, '...and recorded as coming from it';

like errors_for('d/10-a.conf' => "[host:testhost]\nrole = block\n", 'd/20-b.conf' => "[host:testhost]\nrole = report\n",
                'd/94-role.conf' => "[global]\nrole = report\n$DB"),
    qr/role is set differently by more than one file in \[host:testhost\]/, 'two host sections disagreeing are refused';
is BadIPs::Engine::Config::role_from_files(tree(%FLEET, 'd/database.conf' => $OLD_DB)), 'block',
    'the cheap role check still finds the role (so the package knows it is managed, and then refuses)';

done_testing;
