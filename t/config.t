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
    'd/95-fleet.conf' => "[global]\nnever_block_cidrs = 23.116.91.64/29, 198.51.100.45/32, 2001:db8:5400:2e7f::/64\n",
    'd/96-db.conf'    => "[global]\n$DB",
));
is_deeply $err, [], 'report host config is valid';
is $s->{role}, 'report', 'role';
is $s->{db}{schema}, 'badips', 'db schema';
is $s->{db}{port}, 6432, 'db port';
ok $s->{never}->conflict('23.116.91.65'), 'house is never-blocked';
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
like errors_for('d/94-role.conf' => "[global]\nrole = block\nnever_block_cidrs = 23.116.91.64/29, 23.116.91.999\n"), qr/invalid never-block entry/, 'a bad never-block entry refuses the whole config';
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

done_testing;
