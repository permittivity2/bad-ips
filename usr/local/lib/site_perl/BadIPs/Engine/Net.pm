package BadIPs::Engine::Net;

# ============================================================================
# Address and network helpers for the role-based engine (bad-ips 4.0).
#
# Parses and normalises IPv4/IPv6 addresses and CIDR blocks, tests whether
# two blocks overlap, and holds the never-block list. Pure Perl on top of
# core Socket, so the engine needs no extra CPAN modules for this.
#
# Overlap, not containment, is the test that matters for safety: a feed
# range of 23.116.0.0/16 does not sit *inside* the house's 23.116.91.64/29,
# it *contains* it, and blocking it would cut the house off just the same.
# ============================================================================

use strict;
use warnings;

use Socket qw(inet_pton inet_ntop AF_INET AF_INET6);
use Exporter 'import';

our @EXPORT_OK = qw(parse_cidr parse_addr overlaps normalize_addr);

# Never blocked whatever the configuration says: loopback, "this network",
# RFC 1918 private space, link-local, multicast and reserved space, and their
# IPv6 equivalents. A bad config can widen the never-block list but never
# shrink it below this floor.
our @FLOOR = qw(
    0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
    192.168.0.0/16 224.0.0.0/4 240.0.0.0/4
    ::/128 ::1/128 ::ffff:0:0/96 fc00::/7 fe80::/10 ff00::/8
);

=head2 parse_cidr($text)

Parses "ADDR" or "ADDR/LEN" (IPv4 or IPv6). Host bits are cleared, so
"10.1.2.3/8" becomes 10.0.0.0/8. Returns a hashref

    { fam => 4|6, bits => 32|128, len => N, net => <packed>,
      addr => '10.0.0.0', text => '10.0.0.0/8', single => 0|1 }

where C<text> is the bare address for a single host (the form nft prints
for elements of a non-interval set), or undef if the input is not valid.

=cut

sub parse_cidr {
    my ($s) = @_;
    return undef unless defined $s;
    $s =~ s/\A\s+|\s+\z//g;
    my ($addr, $len) = $s =~ m{\A([0-9A-Fa-f.:]+)(?:/(\d{1,3}))?\z} or return undef;

    my ($fam, $bits, $packed);
    if ($addr =~ /:/) {
        ($fam, $bits) = (6, 128);
        $packed = inet_pton(AF_INET6, $addr);
    }
    else {
        return undef unless $addr =~ /\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\z/;
        for my $o ($1, $2, $3, $4) { return undef if $o > 255 || $o =~ /\A0\d/ }
        ($fam, $bits) = (4, 32);
        $packed = inet_pton(AF_INET, $addr);
    }
    return undef unless defined $packed;

    $len = $bits unless defined $len;
    return undef if $len > $bits;

    my $net  = _mask($packed, $len, $bits);
    my $text = inet_ntop($fam == 6 ? AF_INET6 : AF_INET, $net);
    return {
        fam    => $fam,
        bits   => $bits,
        len    => $len + 0,
        net    => $net,
        addr   => $text,
        text   => ($len == $bits ? $text : "$text/$len"),
        single => ($len == $bits ? 1 : 0),
    };
}

=head2 parse_addr($text)

Like parse_cidr, but accepts only a single host address (no prefix, or a
full-length one). Returns undef for anything else.

=cut

sub parse_addr {
    my $p = parse_cidr(@_) or return undef;
    return $p->{single} ? $p : undef;
}

=head2 normalize_addr($text)

The canonical text form of an address ("2001:DB8:0::1" -> "2001:db8::1"),
or undef if invalid. Used to compare with what nft prints.

=cut

sub normalize_addr {
    my $p = parse_addr(@_) or return undef;
    return $p->{text};
}

=head2 overlaps($a, $b)

True if the two parsed blocks share any address, i.e. one contains the
other. Blocks of different families never overlap.

=cut

sub overlaps {
    my ($x, $y) = @_;
    return 0 unless $x && $y && $x->{fam} == $y->{fam};
    my $len = $x->{len} < $y->{len} ? $x->{len} : $y->{len};
    return _mask($x->{net}, $len, $x->{bits}) eq _mask($y->{net}, $len, $y->{bits}) ? 1 : 0;
}

sub _mask {
    my ($packed, $len, $bits) = @_;
    return $packed & pack('B*', ('1' x $len) . ('0' x ($bits - $len)));
}

# ----------------------------------------------------------------------------
# The never-block list
# ----------------------------------------------------------------------------

package BadIPs::Engine::NeverBlock;

use strict;
use warnings;

=head2 BadIPs::Engine::NeverBlock->new(@cidrs)

Builds the list from the floor plus C<@cidrs>. Invalid entries are kept
out of the list and reported by C<errors>, so a caller can refuse to start
rather than run with a list that silently lost an entry.

=cut

sub new {
    my ($class, @cidrs) = @_;
    my $self = bless { list => [], errors => [], seen => {} }, $class;
    $self->_add($_, 'floor') for @BadIPs::Engine::Net::FLOOR;
    $self->_add($_, 'config') for grep { defined && length } @cidrs;
    return $self;
}

sub _add {
    my ($self, $text, $origin) = @_;
    my $p = BadIPs::Engine::Net::parse_cidr($text);
    unless ($p) {
        push @{ $self->{errors} }, "invalid never-block entry '$text'";
        return;
    }
    return if $self->{seen}{ $p->{text} }++;
    push @{ $self->{list} }, $p;
}

sub errors { @{ $_[0]{errors} } }

=head2 conflict($block)

Returns the never-block entry (text) that overlaps C<$block> (a parsed
block or its text), or undef if there is none. An unparseable input is
treated as conflicting, so garbage is never blocked.

=cut

sub conflict {
    my ($self, $x) = @_;
    my $p = ref $x ? $x : BadIPs::Engine::Net::parse_cidr($x);
    return 'invalid' unless $p;
    for my $n (@{ $self->{list} }) {
        return $n->{text} if BadIPs::Engine::Net::overlaps($n, $p);
    }
    return undef;
}

=head2 cidrs($fam)

The list as text, optionally only one family (4 or 6).

=cut

sub cidrs {
    my ($self, $fam) = @_;
    return map { $_->{text} } grep { !defined $fam || $_->{fam} == $fam } @{ $self->{list} };
}

1;
