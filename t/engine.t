#!/usr/bin/perl
# End to end: a mail server (role report) and the edge (role block) sharing
# one REAL PostgreSQL ban list, real log files, and a fake kernel for the
# firewall. Drives BadIPs::Engine::step() with controlled times.
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../usr/local/lib/site_perl", "$FindBin::Bin/lib";
use File::Temp qw(tempdir);
use POSIX qw(strftime);

use TestPg;
use FakeKernel;
use BadIPs::Engine;
use BadIPs::Engine::Store;

my $pg = TestPg->start or plan skip_all => 'no PostgreSQL server binaries';

{   package Quiet;
    sub new { bless { lines => [] }, shift }
    for my $l (qw(debug info warn error)) { no strict 'refs'; *$l = sub { push @{ $_[0]{lines} }, "$l: $_[1]" } }
    sub saw { my ($s, $re) = @_; return scalar grep { /$re/ } @{ $s->{lines} } }
}

my $now = time;
sub rfc3339 { strftime('%Y-%m-%dT%H:%M:%S.000000+00:00', gmtime $_[0]) }
sub nginxts { strftime('%d/%b/%Y:%H:%M:%S +0000', gmtime $_[0]) }
sub append  { my ($f, @l) = @_; open my $fh, '>>', $f or die; print {$fh} map { "$_\n" } @l; close $fh }
sub smtp_fail { my ($ip, $t) = @_; rfc3339($t) . " prod-homelab39 postfix/smtpd[4242]: warning: unknown[$ip]: SASL LOGIN authentication failed: Invalid authentication mechanism: 'LOGIN', sasl_username=(unavailable)" }
sub probe     { my ($ip, $t, $p) = @_; "$ip - - [" . nginxts($t) . "] \"GET $p HTTP/1.1\" 404 162 \"-\" \"zgrab/0.x\"" }

my $NEVER = "never_block_cidrs = 192.0.2.64/29, 198.51.100.45/32, 2001:db8:5400:2e7f::/64\n";
sub host_conf {
    my (%a) = @_;
    my $d = tempdir(CLEANUP => 1);
    mkdir "$d/d";
    open my $fh, '>', "$d/d/90-test.conf" or die;
    print {$fh} "[global]\nrole = $a{role}\nstate_dir = $d\ncache_dir = $d\nreconcile_interval = 30\npush_interval = 5\n"
              . ($a{extra} // '') . $NEVER . ($a{db} ? $pg->db_conf : '') . "\n" . $a{rules};
    close $fh;
    return $d;
}

# --- the mail server ----------------------------------------------------------------
my $mdir = host_conf(role => 'report', db => 1, rules => <<"R");
[rule:postfix-auth]
source  = MAILLOG
format  = rfc3339
match   = ^\\S+ \\S+ postfix/(?:submission/|smtps/)?smtpd\\[\\d+\\]: warning: [^\\s\\[\\]]+\\[(?<ip>[0-9A-Fa-f.:]+)\\]: SASL \\S+ authentication failed
count   = 5
window  = 600
ban     = 3600
service = smtp
R
my $maillog = "$mdir/mail.log";
{ local @ARGV = ("$mdir/d/90-test.conf"); local $^I = ''; while (<>) { s/MAILLOG/$maillog/; print } }
append($maillog, 'warming up');    # the source starts at end-of-file; content written after this is new
my $mlog = Quiet->new;
my $mail = BadIPs::Engine->new(conf_main => "$mdir/none", conf_dir => "$mdir/d", host => 'prod-homelab39', log => $mlog);
ok $mail->start, 'report host starts';
$mail->step($now);

append($maillog, map { smtp_fail('203.0.113.90', $now - 50 + $_) } 1 .. 5);
append($maillog, map { smtp_fail('192.0.2.65', $now - 40 + $_) } 1 .. 6);    # the house
append($maillog, map { smtp_fail('198.51.100.45', $now - 30 + $_) } 1 .. 6);    # offsite
$mail->step($now + 6);
my $st = BadIPs::Engine::Store->new(db => $pg->db, host => 'test');
my $active = $st->load_active($now + 6);
ok exists $active->{'203.0.113.90'}, 'the mail server reported the attacker to the shared list';
ok !exists $active->{'192.0.2.65'} && !exists $active->{'198.51.100.45'}, 'the house and offsite were never reported';
is $mail->{stats}{never_skipped}, 12, 'their 12 lines were skipped by the never-block list';
ok !$mail->{firewall}, 'a report host has no firewall at all';

# --- the edge -------------------------------------------------------------------------
my $k = FakeKernel->new(clock => $now + 10);
my $edir = host_conf(role => 'block', db => 1, extra => "block_interfaces = eth6, eth7\n", rules => <<"R");
[rule:nginx-probe]
source  = ACCESSLOG
format  = nginx
match   = ^(?<ip>[0-9A-Fa-f.:]+) \\S+ \\S+ \\[[^\\]]+\\] "[A-Z]+ /(?:[A-Za-z0-9_.-]+/)?(?:\\.env|\\.git/|wp-login\\.php)
count   = 3
window  = 600
ban     = 604800
service = http
R
my $access = "$edir/access.log";
{ local @ARGV = ("$edir/d/90-test.conf"); local $^I = ''; while (<>) { s/ACCESSLOG/$access/; print } }
append($access, 'warming up');
my $elog = Quiet->new;
my $edge = BadIPs::Engine->new(conf_main => "$edir/none", conf_dir => "$edir/d", host => 'prod-homelab00', log => $elog,
                               runner => $k->runner);
ok $edge->start, 'edge starts';
$edge->step($now + 10);
ok $k->has('badipv4', '203.0.113.90'), 'on its first cycle the edge blocks what the mail server reported';
ok $k->has('never_block', '192.0.2.64/29'), 'never-block in place';
is_deeply $k->{rules}[0], 'badips:iface', 'drops only on the internet-facing interfaces';

# its own detection is blocked at once, not 30 s later
append($access, map { probe('198.51.100.91', $now + 10 + $_, '/.env') } 1 .. 3);
$k->{clock} = $now + 14;
$edge->step($now + 14);
ok $k->has('badipv4', '198.51.100.91'), 'the edge blocks its own detection within the same cycle';
$edge->step($now + 16);    # push is due every 5 s
ok exists $st->load_active($now + 16)->{'198.51.100.91'}, '...and shares it at the next push';

# --- unban, from anywhere -----------------------------------------------------------------
is $st->unban('198.51.100.91', by => 'test', now => $now + 20), 1, 'unban';
$k->{clock} = $now + 50;
$edge->step($now + 50);    # reconcile due (30 s after the last one)
ok !$k->has('badipv4', '198.51.100.91'), 'the edge lifted the unbanned address, its own detection included';
append($access, map { probe('198.51.100.91', $now + 50 + $_, '/.git/config') } 1 .. 3);
$k->{clock} = $now + 60;
$edge->step($now + 60);    # exemptions are refreshed every 60 s
$k->{clock} = $now + 81;
$edge->step($now + 81);
ok !$k->has('badipv4', '198.51.100.91'), 'and does not re-ban it during the exemption';

# --- an nftables reload ---------------------------------------------------------------------
$k->reload;
$k->{clock} = $now + 120;
$edge->step($now + 120);
ok $k->has('badipv4', '203.0.113.90'), 'after an nftables reload the bans are back within one cycle';

# --- the database goes away ------------------------------------------------------------------
my $real_port = $edge->{store}{db}{port};
$edge->{store}{db}{port} = 1;
$edge->{store}{dbh} = undef;
$mail->{store}{db}{port} = 1;
$mail->{store}{dbh} = undef;
append($access, map { probe('198.51.100.92', $now + 150 + $_, '/wp-login.php') } 1 .. 3);
append($maillog, map { smtp_fail('203.0.113.93', $now + 150 + $_) } 1 .. 5);
$k->{clock} = $now + 160;
$edge->step($now + 160);
$mail->step($now + 160);
ok $k->has('badipv4', '198.51.100.92'), 'database down: the edge still blocks its own new detection';
ok $k->has('badipv4', '203.0.113.90'), 'database down: the edge keeps enforcing the last list it had';
is scalar @{ $mail->{queue} }, 1, 'database down: the mail server queues its detection';

# --- a restart while the database is down keeps what was not shared yet ----------------------------
# Positions were saved past the lines that produced these detections, so a
# restart cannot find them again in the logs: only the saved queue has them.
$mail->save_queue;    # what the save slot did at the last step, and what a stop does
ok -s "$mdir/engine-queue.json", 'the unshared detection is on disk';
my $mail2 = BadIPs::Engine->new(conf_main => "$mdir/none", conf_dir => "$mdir/d", host => 'prod-homelab39', log => Quiet->new);
ok $mail2->start, 'restarted report host starts';
is scalar @{ $mail2->{queue} }, 1, 'and takes over the detection the database never received';
is $mail2->{queue}[0]{ip}, '203.0.113.93', '...the right one, evidence and all';
is scalar @{ $mail2->{queue}[0]{lines} }, 5, '...with its log lines';
my $kr = FakeKernel->new(clock => $now + 170);
my $edge_r = BadIPs::Engine->new(conf_main => "$edir/none", conf_dir => "$edir/d", host => 'prod-homelab00', log => Quiet->new,
                                 runner => $kr->runner);
$edge_r->start;
$edge_r->{store}{db}{port} = 1;    # still down
$edge_r->{store}{dbh} = undef;
$edge_r->step($now + 170);
ok $kr->has('badipv4', '198.51.100.92'), 'a restarted edge, database still down, blocks its own unshared detection at once';
is scalar @{ $edge_r->{queue} }, 1, '...and still has it queued for the list';
# an entry whose ban has run out is not worth sharing any more
{
    open my $fh, '<', "$mdir/engine-queue.json" or die; local $/; my $json = <$fh>; close $fh;
    my $q = JSON::decode_json($json);
    push @$q, { %{ $q->[0] }, ip => '203.0.113.99', expires => $now - 1 };
    open $fh, '>', "$mdir/engine-queue.json" or die; print {$fh} JSON::encode_json($q); close $fh;
}
my $mail3 = BadIPs::Engine->new(conf_main => "$mdir/none", conf_dir => "$mdir/d", host => 'prod-homelab39', log => my $m3log = Quiet->new);
$mail3->start;
is scalar @{ $mail3->{queue} }, 1, 'an expired entry in the saved queue is dropped on the way in';
ok $m3log->saw(qr/restored 1 detection not yet shared \(1 expired meanwhile, dropped\)/), '...and said so';

# --- and comes back --------------------------------------------------------------------------------
$edge->{store}{db}{port} = $real_port;
$mail->{store}{db}{port} = $real_port;
$k->{clock} = $now + 400;
$mail->step($now + 400);
$edge->step($now + 400);
is scalar @{ $mail->{queue} }, 0, 'database back: the queued detection is delivered';
ok exists $st->load_active($now + 400)->{'203.0.113.93'}, '...to the shared list';
$k->{clock} = $now + 431;
$edge->step($now + 431);
ok $k->has('badipv4', '203.0.113.93'), '...and the edge blocks it';
ok exists $st->load_active($now + 431)->{'198.51.100.92'}, 'the edge shared what it found while the database was down';

# --- a restart does not re-detect old lines --------------------------------------------------------
$edge->save_positions;
my $k2 = FakeKernel->new(clock => $now + 500);
my $edge2 = BadIPs::Engine->new(conf_main => "$edir/none", conf_dir => "$edir/d", host => 'prod-homelab00', log => Quiet->new,
                                runner => $k2->runner);
$edge2->start;
$edge2->step($now + 500);
is $edge2->{stats}{detections}, 0, 'a restarted edge resumes its logs where it left off (no repeat detections)';
ok $k2->has('badipv4', '203.0.113.90') && $k2->has('badipv4', '198.51.100.92'), 'and, like a rotated-in node, loads every active ban at once';

# --- watch mode ----------------------------------------------------------------------------------------
my $k3 = FakeKernel->new(clock => $now + 600);
my $wdir = host_conf(role => 'block', db => 1, extra => "dry_run = 1\n", rules => '');
my $wlog = Quiet->new;
my $watch = BadIPs::Engine->new(conf_main => "$wdir/none", conf_dir => "$wdir/d", host => 'prod-homelab01', log => $wlog,
                                runner => $k3->runner);
$watch->start;
$watch->step($now + 600);
is_deeply $k3->{calls}, ['state'], 'watch mode only looks: no table, nothing written';
ok $wlog->saw(qr/watch mode: would block \d+ addresses/), 'and says what it would block';

# a host that must not block removes a table an earlier role or run left behind
my $k4 = FakeKernel->new(clock => $now + 700);
$k4->{exists} = 1;                                   # e.g. this node was the blocking edge before
my $watch2 = BadIPs::Engine->new(conf_main => "$wdir/none", conf_dir => "$wdir/d", host => 'prod-homelab01', log => Quiet->new,
                                 runner => $k4->runner);
$watch2->start;
ok !$k4->{exists}, 'watch mode removes a leftover table: watching means blocking nothing';
my $k5 = FakeKernel->new(clock => $now + 700);
$k5->{exists} = 1;
my $rep2 = BadIPs::Engine->new(conf_main => "$mdir/none", conf_dir => "$mdir/d", host => 'prod-homelab40', log => Quiet->new,
                               runner => $k5->runner);
$rep2->start;
ok !$k5->{exists}, 'a report host removes a leftover table too';

done_testing;
