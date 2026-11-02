package BadIPs::Engine::Feed;

# ============================================================================
# Public blocklist feeds for the block role (bad-ips 4.0), e.g. Spamhaus DROP.
#
# A feed is one [feed:NAME] section:
#
#   [feed:spamhaus-drop]
#   urls        = https://www.spamhaus.org/drop/drop.txt, https://www.spamhaus.org/drop/dropv6.txt
#   interval    = 86400
#   min_entries = 100
#
# Each URL is fetched at most once per interval with a conditional GET and
# cached on disk, so a restart or a firewall reload never needs the network.
# Feed entries stay LOCAL: they are never written to the shared ban list.
#
# A download is refused (the previous copy is kept) when it parses to fewer
# than min_entries, or shrinks to under half the previous copy -- both look
# like a truncated or error-page download, and loading one would silently
# lift most of the list. Entries broader than /8 (IPv4) or /16 (IPv6) are
# dropped as implausible.
# ============================================================================

use strict;
use warnings;

use Digest::MD5 qw(md5_hex);
use BadIPs::Engine::Net qw(parse_cidr);

my $MIN_LEN = { 4 => 8, 6 => 16 };

sub new {
    my ($class, %a) = @_;
    return bless {
        name        => $a{name},
        urls        => $a{urls} || [],
        interval    => $a{interval} // 86400,
        min_entries => $a{min_entries} // 10,
        cache_dir   => $a{cache_dir} // '/var/cache/badips',
        timeout     => $a{timeout} // 30,
        ua          => $a{ua},              # injectable for tests
        log         => $a{log},
        per_url     => {},                  # url => [cidr text, ...]
    }, $class;
}

sub name { $_[0]{name} }

sub _cache_base {
    my ($self, $url) = @_;
    return "$self->{cache_dir}/feed-$self->{name}-" . substr(md5_hex($url), 0, 12);
}

sub _log {
    my ($self, $level, $msg) = @_;
    $self->{log}->$level("feed $self->{name}: $msg") if $self->{log};
}

=head2 parse($text)

Returns the valid CIDR entries (text) in a DROP-style list: one
"CIDR ; comment" per line, ';' or '#' comment lines ignored.

=cut

sub parse {
    my ($class_or_self, $text) = @_;
    my (@out, %seen);
    for my $line (split /\r?\n/, $text // '') {
        next if $line =~ /\A\s*(?:[;#]|\z)/;
        my ($tok) = $line =~ /\A\s*([0-9A-Fa-f.:]+(?:\/\d{1,3})?)\s*(?:[;#]|\z)/ or next;
        my $p = parse_cidr($tok) or next;
        next if $p->{len} < $MIN_LEN->{ $p->{fam} };
        push @out, $p->{text} unless $seen{ $p->{text} }++;
    }
    return \@out;
}

=head2 load_cache

Loads every URL's cached copy (used at start, before any fetch).

=cut

sub load_cache {
    my ($self) = @_;
    for my $url (@{ $self->{urls} }) {
        my $f = $self->_cache_base($url) . '.txt';
        next unless -f $f;
        open(my $fh, '<', $f) or next;
        local $/;
        my $entries = $self->parse(scalar <$fh>);
        $self->{per_url}{$url} = $entries if @$entries;
    }
    return scalar @{ $self->entries };
}

=head2 due($now)

True when any URL's cached copy is older than the interval (or missing).

=cut

sub due {
    my ($self, $now) = @_;
    $now //= time;
    for my $url (@{ $self->{urls} }) {
        my @st = stat($self->_cache_base($url) . '.txt');
        return 1 if !@st || $now - $st[9] >= $self->{interval};
    }
    return 0;
}

=head2 refresh($now)

Fetches the URLs that are due. Returns 1 if the combined entry list
changed, else 0. Never throws; failures keep the previous copy.

=cut

sub refresh {
    my ($self, $now) = @_;
    $now //= time;
    my $before = $self->version;
    for my $url (@{ $self->{urls} }) {
        my $base = $self->_cache_base($url);
        my @st   = stat("$base.txt");
        next if @st && $now - $st[9] < $self->{interval};
        eval { $self->_fetch($url, $base, $now); 1 } or $self->_log(warn => "fetch of $url failed: $@");
    }
    return $self->version eq $before ? 0 : 1;
}

sub _ua {
    my ($self) = @_;
    return $self->{ua} if $self->{ua};
    require LWP::UserAgent;
    $self->{ua} = LWP::UserAgent->new(timeout => $self->{timeout}, agent => 'bad-ips/4 (+https://github.com/permittivity2/bad-ips)');
    return $self->{ua};
}

sub _slurp { my ($f) = @_; open(my $fh, '<', $f) or return undef; local $/; my $c = <$fh>; chomp $c if defined $c; $c }
sub _spit  { my ($f, $c) = @_; my $t = "$f.tmp.$$"; open(my $fh, '>', $t) or return 0; print {$fh} $c; close $fh or return 0; rename $t, $f }

sub _fetch {
    my ($self, $url, $base, $now) = @_;
    my %h;
    if (-f "$base.txt") {
        my $etag = _slurp("$base.etag");
        my $lm   = _slurp("$base.lastmod");
        $h{'If-None-Match'}     = $etag if defined $etag && length $etag;
        $h{'If-Modified-Since'} = $lm   if defined $lm   && length $lm;
    }
    my $res = $self->_ua->get($url, %h);
    if ($res->code == 304) {
        utime $now, $now, "$base.txt";
        $self->_log(info => "$url not modified");
        return;
    }
    die $res->status_line . "\n" unless $res->is_success;

    my $content = $res->decoded_content // '';
    my $entries = $self->parse($content);
    my $prev    = $self->{per_url}{$url} || [];
    die sprintf("refused: only %d entries (min_entries %d)\n", scalar @$entries, $self->{min_entries})
        if @$entries < $self->{min_entries};
    die sprintf("refused: shrank from %d to %d entries\n", scalar @$prev, scalar @$entries)
        if @$prev && @$entries < @$prev / 2;

    _spit("$base.txt", $content) or die "cannot write $base.txt: $!\n";
    if (my $e = $res->header('ETag'))          { _spit("$base.etag", $e) }
    if (my $l = $res->header('Last-Modified')) { _spit("$base.lastmod", $l) }
    $self->{per_url}{$url} = $entries;
    $self->_log(info => sprintf "%s: %d entries", $url, scalar @$entries);
}

=head2 entries

All entries across the feed's URLs, de-duplicated, sorted.

=cut

sub entries {
    my ($self) = @_;
    my %all;
    $all{$_} = 1 for map { @$_ } values %{ $self->{per_url} };
    return [ sort keys %all ];
}

sub version { md5_hex(join("\n", @{ $_[0]->entries })) }

1;
