#!/usr/bin/perl
# The rule engine (BadIPs::Engine::Rules) and the shipped 60-rules.conf.
#
# Fixture lines are real lines from the fleet's logs (2026-11-02) with the
# addresses swapped for documentation ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24) and the usernames replaced.
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../usr/local/lib/site_perl";
use Config::Tiny;

use BadIPs::Engine::Rules;

my $conf = Config::Tiny->read("$FindBin::Bin/../usr/local/etc/badips.d/60-rules.conf")
    or die "cannot read 60-rules.conf: " . Config::Tiny->errstr;

my %R;
for my $section (sort keys %$conf) {
    next unless $section =~ /^rule:(.+)/;
    my ($rule, $err) = BadIPs::Engine::Rules::compile_rule($1, $conf->{$section});
    is_deeply $err, [], "shipped rule $1 compiles";
    $R{$1} = $rule;
}
is_deeply [ sort keys %R ], [qw(dovecot-auth nginx-catchall-flood nginx-probe postfix-abuse postfix-auth postfix-auth-slow)],
    'all six shipped rules present';

sub m1 { my ($rule, $line) = @_; my @r = BadIPs::Engine::Rules::match_line($R{$rule}, $line); return \@r }

# --- nginx-probe --------------------------------------------------------------
my $ng = '[02/Nov/2026:12:59:38 -0600]';
for my $path ('/.env', '/.env.production', '/api/.env', '/.git/config', '/wp-login.php', '/xmlrpc.php',
              '/phpMyAdmin/index.php', '/cgi-bin/luci', '/vendor/phpunit/src/Util/PHP/eval-stdin.php',
              '/.aws/credentials', '/actuator/health', '/boaform/admin/formLogin', '/HNAP1/') {
    is_deeply m1('nginx-probe', qq{203.0.113.10 - - $ng "GET $path HTTP/1.1" 404 162 "-" "Mozilla/5.0"}),
        ['203.0.113.10', 1], "probe path matches: $path";
}
for my $path ('/', '/?_task=mail&_action=refresh', '/favicon.ico', '/robots.txt', '/s/a07f58ca/download',
              '/a/b/.env', '/drive/files/environment.txt') {
    is_deeply m1('nginx-probe', qq{203.0.113.10 - - $ng "GET $path HTTP/1.1" 200 162 "-" "Mozilla/5.0"}),
        [], "ordinary path does not match: $path";
}
is_deeply m1('nginx-probe', qq{198.51.100.5 - - $ng "GET /index.html HTTP/1.1" 200 5 "-" "x \\x22GET /.env HTTP/1.1\\x22"}),
    [], 'a probe path inside the user agent does not match';
is_deeply m1('nginx-probe', qq{198.51.100.5 - - $ng "GET /.env?next=8.8.8.8 HTTP/1.1" 404 5 "-" "8.8.4.4"}),
    ['198.51.100.5', 1], 'addresses in the URL or user agent are never taken as the client';

# --- nginx-catchall-flood -----------------------------------------------------
is_deeply m1('nginx-catchall-flood', qq{203.0.113.11 - - $ng "GET / HTTP/1.1" 404 162 "-" "-"}),
    ['203.0.113.11', 1], 'a catch-all 404 matches';
is_deeply m1('nginx-catchall-flood', qq{203.0.113.11 - - $ng "GET /404 HTTP/1.1" 200 162 "-" "-"}),
    [], '404 in the path with a 200 status does not match';
is_deeply m1('nginx-catchall-flood', qq{203.0.113.11 - - $ng "\\x16\\x03\\x01" 400 157 "-" "-"}),
    [], 'a 400 does not match';

# --- postfix-auth -------------------------------------------------------------
my $pf = '2026-11-02T15:34:30.031181-06:00 prod-homelab39';
is_deeply m1('postfix-auth', "$pf postfix/smtpd[1102378]: warning: unknown[198.51.100.7]: SASL LOGIN authentication failed: Invalid authentication mechanism: 'LOGIN', sasl_username=(unavailable)"),
    ['198.51.100.7', 1], 'SMTP auth failure (bot trying LOGIN)';
is_deeply m1('postfix-auth', "$pf postfix/submission/smtpd[42]: warning: mail.example.net[198.51.100.8]: SASL PLAIN authentication failed: authentication failure, sasl_username=someone\@example.org"),
    ['198.51.100.8', 1], 'submission auth failure with a resolved hostname';
is_deeply m1('postfix-auth', "$pf postfix/smtpd[42]: connect from unknown[198.51.100.7]"),
    [], 'an ordinary connect does not match';
is_deeply m1('postfix-auth', "$pf dovecot: imap-login: Login aborted: (auth failed, 1 attempts in 2 secs) (auth_failed): user=<warning: unknown[8.8.8.8]: SASL LOGIN authentication failed>, method=PLAIN, rip=198.51.100.9, lip=192.0.2.66"),
    [], 'a postfix-looking username inside a dovecot line does not match the postfix rule';

# --- postfix-abuse ------------------------------------------------------------
is_deeply m1('postfix-abuse', "$pf postfix/smtpd[1100357]: improper command pipelining after CONNECT from unknown[192.0.2.20]: \\003\\000\\000,'\\340Cookie: mstshash=Domain\\r\\n"),
    ['192.0.2.20', 1], 'pipelining before the greeting';
is_deeply m1('postfix-abuse', "$pf postfix/submission/smtpd[1033285]: warning: non-SMTP command from scan.example.com[192.0.2.21]: \\026\\003\\001\\000"),
    ['192.0.2.21', 1], 'non-SMTP command';
is_deeply m1('postfix-abuse', "$pf postfix/smtpd[1101709]: NOQUEUE: reject: RCPT from unknown[192.0.2.22]: 554 5.7.1 <victim\@example.com>: Relay access denied; from=<x\@example.net> to=<victim\@example.com> proto=ESMTP helo=<example>"),
    ['192.0.2.22', 1], 'open-relay attempt';
is_deeply m1('postfix-abuse', "$pf postfix/smtpd[1101709]: NOQUEUE: reject: RCPT from mx.example.org[192.0.2.23]: 550 5.1.1 <nosuch\@mailmasker.org>: Recipient address rejected: User unknown in virtual mailbox table;"),
    [], 'a mistyped recipient from a real mail server does not count as abuse';
is_deeply m1('postfix-abuse', "$pf postfix/smtpd[1]: NOQUEUE: reject: RCPT from unknown[192.0.2.24]: 554 5.7.1 <8.8.8.8\@[8.8.4.4]>: Relay access denied;"),
    ['192.0.2.24', 1], 'addresses inside the recipient are never taken as the client';

# --- dovecot-auth -------------------------------------------------------------
my $dv = '2026-11-02T15:17:49.367343-06:00 prod-homelabvm62 dovecot: imap-login:';
is_deeply m1('dovecot-auth', "$dv Login aborted: Connection closed (auth failed, 2 attempts in 12 secs) (auth_failed): user=<someone\@example.net>, method=PLAIN, rip=203.0.113.30, lip=192.0.2.66, TLS, session=<PAbKrFFfk80kQ9fj>"),
    ['203.0.113.30', 2], 'IMAP auth failure, weighted by its attempt count';
is_deeply m1('dovecot-auth', "$dv Disconnected: Connection closed (auth failed, 3 attempts in 15 secs): user=<x>, method=PLAIN, rip=203.0.113.31, lip=10.50.2.206"),
    ['203.0.113.31', 3], 'the older dovecot wording matches too';
is_deeply m1('dovecot-auth', "$dv Login aborted: Connection closed (auth failed, 1 attempts in 2 secs) (auth_failed): user=<x>, method=PLAIN, rip=8.8.8.8, lip=1.1.1.1, TLS, session=<y>, method=PLAIN, rip=203.0.113.32, lip=192.0.2.66, TLS, session=<z>"),
    ['203.0.113.32', 1], 'SPOOF: a fake rip= typed into the username is ignored; the last rip= wins';
is_deeply m1('dovecot-auth', "$dv Login aborted: Connection closed (auth failed, 999 attempts in 1 secs) (auth_failed): user=<x>, method=PLAIN, rip=203.0.113.33, lip=192.0.2.66"),
    ['203.0.113.33', 10], 'an absurd attempt count is capped at max_weight';
is_deeply m1('dovecot-auth', "$dv Login: user=<x>, method=PLAIN, rip=203.0.113.34, lip=192.0.2.66, mpid=1, TLS"),
    [], 'a successful login does not match';
is_deeply m1('dovecot-auth', "$dv Login aborted: Connection closed (no auth attempts in 0 secs) (no_auth_attempts): user=<>, rip=203.0.113.35, lip=192.0.2.66"),
    [], 'a connection with no auth attempt does not match';

# --- postfix-auth-slow ------------------------------------------------------
{
    my $slow = BadIPs::Engine::Counter->new(rule => $R{'postfix-auth-slow'});
    my $det;
    # 408 attempts over five days at ~3 an hour (the real worst case)
    for my $i (0 .. 30) { $det ||= $slow->observe('203.0.113.60', 50_000 + 1200 * $i, 1, "slow $i") }
    ok $det, 'a patient guesser (one try every 20 minutes) is caught by the slow rule';
    is $det->{expires} - $det->{last}, 86400, 'slow rule bans for a day';
    my $fast = BadIPs::Engine::Counter->new(rule => $R{'postfix-auth'});
    my $fdet;
    for my $i (0 .. 30) { $fdet ||= $fast->observe('203.0.113.60', 50_000 + 1200 * $i, 1, "slow $i") }
    ok !$fdet, 'the same pattern never trips the fast rule';
}

# --- compile errors -----------------------------------------------------------
my %ok = (source => '/var/log/x.log', match => '^(?<ip>\S+) x', count => 1, window => 60, ban => 60);
sub errs { my %c = (%ok, @_); my ($r, $e) = BadIPs::Engine::Rules::compile_rule('t', \%c); return $e }
like errs(match => '^(\S+) x')->[0], qr/\(\?<ip>/, 'a pattern without (?<ip>) is refused';
like errs(match => '^(?<ip>[)')->[0], qr/does not compile/, 'a broken pattern is refused';
like errs(journal => 'postfix')->[0], qr/not both/, 'source and journal together are refused';
like errs(source => 'relative.log')->[0], qr/absolute/, 'a relative source path is refused';
like errs(ban => 30)->[0], qr/at least 60/, 'a ban under 60 s is refused';
like errs(count => 0)->[0], qr/count/, 'a zero count is refused';
like errs(format => 'iso')->[0], qr/format/, 'an unknown format is refused';
is_deeply errs(), [], 'the minimal valid rule compiles';

# --- timestamps ---------------------------------------------------------------
my $t = 1762119270;    # 2025-11-02T21:34:30Z
is BadIPs::Engine::Rules::line_time('2025-11-02T15:34:30.031181-06:00 h p: m', 'rfc3339'), $t, 'rfc3339 with offset';
is BadIPs::Engine::Rules::line_time('2025-11-02T21:34:30Z h p: m', 'auto'), $t, 'rfc3339 Z, auto-detected';
is BadIPs::Engine::Rules::line_time('203.0.113.1 - - [02/Nov/2025:15:34:30 -0600] "GET / HTTP/1.1" 200 1', 'nginx'), $t, 'nginx';
is BadIPs::Engine::Rules::line_time('203.0.113.1 - - [02/Nov/2025:15:34:30 -0600] "GET /"', 'auto'), $t, 'nginx, auto-detected';
ok !defined BadIPs::Engine::Rules::line_time('no time here', 'auto'), 'no timestamp -> undef';
ok !defined BadIPs::Engine::Rules::line_time('203.0.113.1 - - [02/Nov/2025:15:34:30 -0600]', 'rfc3339'), 'wrong explicit format -> undef';
ok defined BadIPs::Engine::Rules::line_time('Nov  2 15:34:30 host sshd[1]: x', 'syslog', time), 'traditional syslog';

# --- counting -----------------------------------------------------------------
my ($rule) = BadIPs::Engine::Rules::compile_rule('c', { %ok, count => 5, window => 600, ban => 3600 });
my $c = BadIPs::Engine::Counter->new(rule => $rule);
my $d;
$d = $c->observe('203.0.113.50', 1000 + 100 * $_, 1, "line $_") for 0 .. 3;
ok !$d, 'four hits do not reach a count of five';
$d = $c->observe('203.0.113.50', 1400, 1, 'line 4');
ok $d, 'the fifth hit within the window is a detection';
is $d->{ip}, '203.0.113.50', 'detection ip';
is $d->{expires}, 1400 + 3600, 'ban runs from the last hit';
is $d->{first}, 1000, 'first hit time kept';
is scalar @{ $d->{lines} }, 5, 'evidence lines kept';
ok !$c->observe('203.0.113.50', 1401, 5, 'again'), 'an immediate repeat is suppressed (ban still has > half to run)';

my $c2 = BadIPs::Engine::Counter->new(rule => $rule);
my $hit;
for my $i (0 .. 9) { $hit ||= $c2->observe('203.0.113.51', 10_000 + 700 * $i, 1, "slow $i") }
ok !$hit, 'hits spread wider than the window never trigger';

my $c3 = BadIPs::Engine::Counter->new(rule => $rule);
ok !$c3->observe('203.0.113.52', 5000, 2, 'w2'), 'weight 2';
ok $c3->observe('203.0.113.52', 5001, 3, 'w3'), 'weights add up (2 + 3 = 5)';

my $c4 = BadIPs::Engine::Counter->new(rule => $rule);
$c4->observe('203.0.113.53', $_, 1, 'x') for (2000, 1990, 1980, 1970);
ok $c4->observe('203.0.113.53', 1960, 1, 'x'), 'out-of-order hits within the window still count';

my $c5 = BadIPs::Engine::Counter->new(rule => $rule, max_tracked => 100);
$c5->observe("198.51.100.$_", 7000, 1, 'x') for 1 .. 250;
ok scalar(keys %{ $c5->{hits} }) <= 100, 'memory stays bounded under a flood of one-hit sources';

$c->expire(1400 + 3600 + 1);
ok !exists $c->{reported}{'203.0.113.50'}, 'expire() forgets finished bans';

done_testing;
