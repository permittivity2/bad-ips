#!/usr/bin/perl
# The Prometheus feed (item 43): what the daemon writes to node_exporter's
# textfile directory. No database: the block role runs on its own detections,
# the firewall is a fake kernel whose counters the test sets.
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../usr/local/lib/site_perl", "$FindBin::Bin/lib";
use File::Temp qw(tempdir);
use POSIX qw(strftime);

use FakeKernel;
use BadIPs::Engine;
use BadIPs::Engine::Metrics;

{   package Quiet;
    sub new { bless { lines => [] }, shift }
    for my $l (qw(debug info warn error)) { no strict 'refs'; *$l = sub { push @{ $_[0]{lines} }, "$l: $_[1]" } }
    sub saw { my ($s, $re) = @_; return scalar grep { /$re/ } @{ $s->{lines} } }
}

my $now = time;
sub nginxts { strftime('%d/%b/%Y:%H:%M:%S +0000', gmtime $_[0]) }
sub append  { my ($f, @l) = @_; open my $fh, '>>', $f or die; print {$fh} map { "$_\n" } @l; close $fh }
sub probe   { my ($ip, $t) = @_; "$ip - - [" . nginxts($t) . "] \"GET /.env HTTP/1.1\" 404 162 \"-\" \"zgrab/0.x\"" }

my $d = tempdir(CLEANUP => 1);
my $out = "$d/out";
mkdir "$d/d"; mkdir $out;
my $access = "$d/access.log";
open my $fh, '>', "$d/d/90-test.conf" or die;
print {$fh} <<"C";
[global]
role = block
state_dir = $d
cache_dir = $d
metrics_dir = $out
metrics_interval = 30
reconcile_interval = 30
never_block_cidrs = 192.0.2.64/29
block_interfaces = eth6, eth7

[rule:nginx-probe]
source  = $access
format  = nginx
match   = ^(?<ip>[0-9A-Fa-f.:]+) \\S+ \\S+ \\[[^\\]]+\\] "[A-Z]+ /\\.env
count   = 3
window  = 600
ban     = 3600
service = http
C
close $fh;
append($access, 'warming up');

my $k = FakeKernel->new(clock => $now);
my $log = Quiet->new;
my $e = BadIPs::Engine->new(conf_main => "$d/none", conf_dir => "$d/d", host => 'edge-test', log => $log, runner => $k->runner);
ok $e->start, 'edge starts';
$e->step($now);
append($access, map { probe('203.0.113.9', $now - 5 + $_) } 1 .. 3);
append($access, map { probe('192.0.2.66', $now - 5 + $_) } 1 .. 3);    # the house: never blocked
$k->{clock} = $now + 2;
$e->step($now + 2);

# the kernel's counters: 7 web knocks and 2 smtp knocks from banned addresses,
# 30 SSH packets in all, the ban drop rule counted 12 (so 3 hit other ports)
@{ $k->{rule_packets} }{ 'badips:knock:ban4:web', 'badips:knock:ban4:smtp', 'badips:knock_all:ssh', 'badips:ban4' } = (7, 2, 30, 12);
$k->{element_packets}{badipv4}{'203.0.113.9'} = 4;

my $text = BadIPs::Engine::Metrics::render($e, $now + 3, $e->{firewall}->state);
like $text, qr/^badips_mode 3$/m, 'block role, not watch mode: mode 3';
like $text, qr/^badips_detections_total 1$/m, 'one address caught';
like $text, qr/^badips_detections_by_rule_total\{rule="nginx-probe"\} 1$/m, '...and by which rule';
like $text, qr/^badips_never_block_refusals_total 3$/m, 'the house address was left alone, its 3 lines counted';
like $text, qr/^badips_blocked_addresses 1$/m, 'one address on the ban list';
like $text, qr/^badips_knocks_total\{group="web"\} 7$/m, 'web knocks';
like $text, qr/^badips_knocks_total\{group="smtp"\} 2$/m, 'smtp knocks';
like $text, qr/^badips_knocks_total\{group="other"\} 3$/m, 'other = the drop total minus the named groups';
like $text, qr/^badips_drops_total\{list="ban4"\} 12$/m, 'drops by list';
like $text, qr/^badips_ssh_connection_attempts_total 30$/m, 'every SSH attempt, banned or not';
like $text, qr/^badips_banned_addresses_still_knocking 1$/m, 'one banned address kept knocking';
like $text, qr/^badips_database_up 0$/m, 'no database in this test';
like $text, qr/^badips_seconds_since_sync [0-9]+$/m, 'seconds since the last sync';
my %help; $help{$_}++ for $text =~ /^# HELP (\S+)/mg;
ok !(grep { $_ > 1 } values %help), 'each metric is described once';

# publishing: one file, written whole, readable by node_exporter
ok BadIPs::Engine::Metrics::publish($e, $now + 3), 'publish succeeds';
ok -f "$out/badips.prom", 'badips.prom is in the directory';
ok !-e "$out/.badips.prom.tmp", 'no temporary file left behind';
is((stat "$out/badips.prom")[2] & 07777, 0644, 'mode 0644');

# step() publishes on its own schedule
unlink "$out/badips.prom";
$e->{next}{metrics} = 0;
$e->step($now + 40);
ok -f "$out/badips.prom", 'the loop publishes every metrics_interval';

# a directory that cannot be written is a warning, once, and nothing worse
$e->{s}{metrics_dir} = "$d/missing";
ok !BadIPs::Engine::Metrics::publish($e, $now + 50), 'an unwritable directory is reported as a failure';
ok !BadIPs::Engine::Metrics::publish($e, $now + 51), '...every time';
is $log->saw(qr/metrics: cannot write/), 1, '...but logged once';
$e->{s}{metrics_dir} = '';
ok BadIPs::Engine::Metrics::publish($e, $now + 52), 'metrics_dir empty = publishing is switched off';

done_testing;
