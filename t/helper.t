#!/usr/bin/perl
# The privileged helper's role-mode request parser and nft script builder,
# via `bad_ips_nft render` (prints what sync would do; runs no nft).
use strict;
use warnings;
use Test::More;
use FindBin;
use IPC::Open3 qw(open3);

my $helper = "$FindBin::Bin/../usr/local/sbin/bad_ips_nft";

sub render {
    my ($req) = @_;
    my $pid = open3(my $in, my $out, undef, $^X, '-T', $helper, 'render');
    print {$in} $req;
    close $in;
    my $o = do { local $/; <$out> } // '';
    waitpid($pid, 0);
    return ($? >> 8, $o);
}

# --- replace --------------------------------------------------------------------
my ($rc, $o) = render(<<'REQ');
mode replace
iface eth6
iface eth7
dns_accept 1
never 10.0.0.0/8
never 192.0.2.64/29
never 2001:db8:5400:2e7f::/64
feed 1.10.16.0/20
feed 2001:678:254::/48
ban 203.0.113.7 600
ban 2001:db8::7 99999999
REQ
is $rc, 0, 'a valid replace request renders';
my ($persist, $tx) = $o =~ /\A### persistent\n(.*)### transaction\n(.*)\z/s;
like $tx, qr/\Atable inet badips \{\}\ndelete table inet badips\ntable inet badips \{/, 'replace swaps the table in one transaction';
like $tx, qr/iifname != \{ "eth6", "eth7" \} accept comment "badips:iface"/, 'drops only on the named interfaces';
like $tx, qr/th dport 53 accept comment "badips:dns"/, 'DNS is accepted ahead of the drops';
like $tx, qr/203\.0\.113\.7 timeout 600s/, 'ban with its timeout';
like $tx, qr/2001:db8::7 timeout 2592000s/, 'an over-long timeout is capped at 30 days';
like $tx, qr/never_block \{.*192\.0\.2\.64\/29/s, 'never-block entries in the set';
my @order = $tx =~ /comment "(badips:\w+)"/g;
is_deeply \@order, [qw(badips:iface badips:never4 badips:never6 badips:dns badips:ban4 badips:ban6 badips:feed4 badips:feed6)],
    'never-block and DNS accepts come BEFORE any drop';
like $persist, qr/192\.0\.2\.64\/29/, 'the persistent file carries the never-block list (survives a reload)';
unlike $persist, qr/203\.0\.113\.7|1\.10\.16\.0/, '...but no bans or feed ranges (the daemon restores those)';
like $persist, qr/table inet badips \{\}\ndelete table inet badips\n/, 'the persistent file is safe to load on its own, too';

($rc, $o) = render("mode replace\ndns_accept 0\nnever 10.0.0.0/8\n");
unlike $o, qr/badips:dns/, 'dns_accept 0 leaves the DNS rule out';
unlike $o, qr/badips:iface/, 'no interfaces: drops on every interface';

# --- apply ---------------------------------------------------------------------
($rc, $o) = render("mode apply\nunban 203.0.113.9\nban 203.0.113.7 60\nban 2001:db8::7 60\nfeedreset\nfeed 1.10.16.0/20\n");
is $rc, 0, 'a valid apply request renders';
($tx) = $o =~ /### transaction\n(.*)\z/s;
like $tx, qr/\Aflush set inet badips feedv4\nflush set inet badips feedv6\nadd element inet badips feedv4 \{ 1\.10\.16\.0\/20 \}\n/, 'feedreset empties then refills the feed sets';
like $tx, qr/destroy element inet badips badipv4 \{ 203\.0\.113\.9 \}\n.*add element inet badips badipv4 \{ 203\.0\.113\.7 timeout 60s \}/s,
    'removals (destroy: no error if already gone) before additions';
like $tx, qr/add element inet badips badipv6 \{ 2001:db8::7 timeout 60s \}/, 'v6 goes to the v6 set';

my $many = "mode apply\n" . join('', map { "ban 198.51.100.$_ 60\n" } 1 .. 254) . join('', map { "ban 203.0.113.$_ 60\n" } 1 .. 254);
($rc, $o) = render($many);
my @stmts = $o =~ /^add element inet badips badipv4/mg;
is scalar @stmts, 2, 'large lists are split into statements of at most 500 elements';

# --- refusals --------------------------------------------------------------------
for my $bad (
    [ "ban 203.0.113.7 60\n",                       'no mode' ],
    [ "mode wipe\n",                                'unknown mode' ],
    [ "mode apply\nmode apply\n",                   'mode twice' ],
    [ "mode apply\nban 203.0.113.0/24 60\n",        'a CIDR ban' ],
    [ "mode apply\nban 203.0.113.7 0\n",            'a zero ttl' ],
    [ "mode apply\nban 203.0.113.7 -1\n",           'a negative ttl' ],
    [ "mode apply\nban 300.1.1.1 60\n",             'an invalid address' ],
    [ "mode apply\nban 1.2.3.4;flush ruleset 60\n", 'shell/nft metacharacters' ],
    [ "mode apply\nnever 10.0.0.0/8\n",             'never-block changes in apply mode' ],
    [ "mode apply\nfeed 1.10.16.0/20\n",            'feed lines without feedreset' ],
    [ "mode replace\nunban 203.0.113.7\n",          'unban in replace mode' ],
    [ "mode replace\niface eth6\"; drop\n",         'a hostile interface name' ],
    [ "mode replace\nnever 1.2.3.4-1.2.3.9\n",      'a range' ],
    [ "mode apply\nrm -rf /\n",                     'an unknown command' ],
) {
    my ($code) = render($bad->[0]);
    isnt $code, 0, "refused: $bad->[1]";
}

done_testing;
