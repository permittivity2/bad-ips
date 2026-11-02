#!/usr/bin/perl
# Blocklist feeds (BadIPs::Engine::Feed). No network: a fake user agent.
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../usr/local/lib/site_perl";
use File::Temp qw(tempdir);

use BadIPs::Engine::Feed;

# --- parsing a DROP-style list ------------------------------------------------
my $sample = <<'TXT';
; Spamhaus DROP List 2026/11/02 - (c) 2026 The Spamhaus Project SLU
; https://www.spamhaus.org/drop/drop.txt
; Last-Modified: Mon, 02 Nov 2026 20:21:09 GMT
1.10.16.0/20 ; SBL256894
1.19.0.0/16 ; SBL434604
5.0.0.0/7 ; implausibly broad
1.19.0.0/16 ; duplicate
not-an-address ; junk
2001:678:254::/48 ; SBL697648
2a00::/12 ; implausibly broad v6
203.0.113.0/24
TXT
is_deeply(BadIPs::Engine::Feed->parse($sample),
    [ '1.10.16.0/20', '1.19.0.0/16', '2001:678:254::/48', '203.0.113.0/24' ],
    'comments, junk, duplicates and implausibly broad ranges are dropped');

# --- fetching -------------------------------------------------------------------
{
    package FakeRes;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub code { $_[0]{code} }
    sub is_success { $_[0]{code} == 200 }
    sub status_line { "$_[0]{code} test" }
    sub decoded_content { $_[0]{body} }
    sub header { $_[0]{headers}{ $_[1] } }
    package FakeUA;
    sub new { bless { queue => [], seen => [] }, shift }
    sub get { my ($s, $url, %h) = @_; push @{ $s->{seen} }, { url => $url, %h }; return shift @{ $s->{queue} } }
}

my $dir = tempdir(CLEANUP => 1);
my $ua  = FakeUA->new;
my $big = join('', map { "10.$_.0.0/16 ; x\n" } 1 .. 30);    # 10/8 is private, but the feed does not judge that
$big =~ s/^10\./100./mg;                                        # 100.N.0.0/16, 30 entries
my $f = BadIPs::Engine::Feed->new(name => 't', urls => ['https://example.test/drop.txt'], interval => 3600,
                                  min_entries => 20, cache_dir => $dir, ua => $ua);
ok $f->due(1_000_000), 'due when nothing is cached';
push @{ $ua->{queue} }, FakeRes->new(code => 200, body => $big, headers => { ETag => '"v1"' });
is $f->refresh(1_000_000), 1, 'first fetch changes the list';
is scalar @{ $f->entries }, 30, '30 entries';
ok !$f->due(time), 'not due right after a fetch';

# a truncated download is refused and the previous copy kept
my $f2 = BadIPs::Engine::Feed->new(name => 't', urls => ['https://example.test/drop.txt'], interval => 3600,
                                   min_entries => 5, cache_dir => $dir, ua => $ua);
is $f2->load_cache, 30, 'a restart loads the cached copy without the network';
utime 0, 0, glob("$dir/feed-t-*.txt");                          # make it stale
push @{ $ua->{queue} }, FakeRes->new(code => 200, body => join('', map { "100.$_.0.0/16\n" } 1 .. 10));
is $f2->refresh(time), 0, 'a list that shrank by more than half is refused';
is scalar @{ $f2->entries }, 30, '...and the previous 30 entries are kept';
is $ua->{seen}[-1]{'If-None-Match'}, '"v1"', 'the refetch was conditional (ETag)';

push @{ $ua->{queue} }, FakeRes->new(code => 200, body => "; empty\n");
utime 0, 0, glob("$dir/feed-t-*.txt");
my $f3 = BadIPs::Engine::Feed->new(name => 't', urls => ['https://example.test/drop.txt'], interval => 3600,
                                   min_entries => 5, cache_dir => $dir, ua => $ua);
$f3->load_cache;
is $f3->refresh(time), 0, 'an empty list (error page) is refused';
is scalar @{ $f3->entries }, 30, '...previous copy kept';

push @{ $ua->{queue} }, FakeRes->new(code => 304);
utime 0, 0, glob("$dir/feed-t-*.txt");
is $f3->refresh(time), 0, '304 Not Modified keeps the list';
ok !$f3->due(time), 'and counts as fresh';

push @{ $ua->{queue} }, FakeRes->new(code => 500);
utime 0, 0, glob("$dir/feed-t-*.txt");
is $f3->refresh(time), 0, 'a server error keeps the list';
is scalar @{ $f3->entries }, 30, '...previous copy kept';

done_testing;
