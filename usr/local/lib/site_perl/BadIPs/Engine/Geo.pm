package BadIPs::Engine::Geo;

# ============================================================================
# bad-ips 4.2: which country and network owner an address belongs to.
#
# Data: DB-IP "Lite" country and ASN files (CC BY 4.0 -- https://db-ip.com;
# a dashboard that shows the results must credit them). They are CSV, tens of
# MB. build() turns them into sorted fixed-width binary files that lookup()
# binary-searches straight from disk, so a lookup costs a few reads and the
# daemon holds almost nothing in memory.
#
#   country4.bin  start(4) end(4) cc(2)        country6.bin  start(16) end(16) cc(2)
#   asn4.bin      start(4) end(4) asn(4)       asn6.bin      start(16) end(16) asn(4)
#   asn_org.tsv   "asn\torganisation\n", sorted by asn (numeric)
#
# Addresses are compared as big-endian byte strings, which sort the same way
# as the numbers do.
# ============================================================================

use strict;
use warnings;

use Socket qw(inet_pton AF_INET AF_INET6);
use IO::Uncompress::Gunzip qw($GunzipError);

our $VERSION = '4.3.0';

my %REC = (country4 => [4, 2], country6 => [16, 2], asn4 => [4, 4], asn6 => [16, 4]);

sub new {
    my ($class, %a) = @_;
    return bless { dir => $a{dir}, org => undef }, $class;
}

# True when the data files are there.
sub available {
    my ($self) = @_;
    return -s "$self->{dir}/country4.bin" ? 1 : 0;
}

sub _bin {
    my ($ip) = @_;
    my $b;
    if    ($ip =~ /\A\d{1,3}(?:\.\d{1,3}){3}\z/) { $b = inet_pton(AF_INET, $ip);  return defined $b ? (4, $b) : () }
    elsif ($ip =~ /:/)                              { $b = inet_pton(AF_INET6, $ip); return defined $b ? (6, $b) : () }
    return;
}

# Binary search of one data file for the record whose range holds $key.
sub _find {
    my ($self, $kind, $key) = @_;
    my ($klen, $vlen) = @{ $REC{$kind} };
    my $rec = 2 * $klen + $vlen;
    open(my $fh, '<:raw', "$self->{dir}/$kind.bin") or return undef;
    my $n = (-s $fh) / $rec;
    my ($lo, $hi) = (0, $n - 1);
    while ($lo <= $hi) {
        my $mid = int(($lo + $hi) / 2);
        seek($fh, $mid * $rec, 0);
        read($fh, my $buf, $rec) == $rec or return undef;
        my ($s, $e, $v) = unpack("a$klen a$klen a$vlen", $buf);
        if    ($key lt $s) { $hi = $mid - 1 }
        elsif ($key gt $e) { $lo = $mid + 1 }
        else                { return $v }
    }
    return undef;
}

=head2 lookup($ip)

{ country => 'US'|undef, asn => N|undef, org => 'name'|undef }

=cut

sub lookup {
    my ($self, $ip) = @_;
    my ($fam, $key) = _bin($ip) or return { country => undef, asn => undef, org => undef };
    my $cc  = $self->_find("country$fam", $key);
    my $asn = $self->_find("asn$fam", $key);
    $asn = unpack('N', $asn) if defined $asn;
    undef $cc if defined $cc && $cc eq '--';
    undef $asn if defined $asn && $asn == 0;
    return { country => $cc, asn => $asn, org => defined $asn ? $self->_org($asn) : undef };
}

sub _org {
    my ($self, $asn) = @_;
    open(my $fh, '<:raw', "$self->{dir}/asn_org.tsv") or return undef;
    my ($lo, $hi) = (0, -s $fh);
    # bisect on byte offsets, then scan forward to a line start
    while ($hi - $lo > 4096) {
        my $mid = int(($lo + $hi) / 2);
        seek($fh, $mid, 0);
        <$fh>;
        my $line = <$fh>;
        if (!defined $line) { $hi = $mid; next }
        my ($a) = split /\t/, $line;
        if ($a < $asn) { $lo = $mid } else { $hi = $mid }
    }
    seek($fh, $lo, 0);
    <$fh> if $lo;
    while (my $line = <$fh>) {
        chomp $line;
        my ($a, $org) = split /\t/, $line, 2;
        return $org if $a == $asn;
        return undef if $a > $asn;
    }
    return undef;
}

=head2 build(country => FILE, asn => FILE, dir => DIR)

Reads DB-IP Lite CSVs (plain or .gz) and writes the data files into DIR,
each to a temporary name and then renamed, so a running daemon never sees a
half-written file. Dies on a file that does not look like what it should
(too few rows). Returns { country => N, asn => N }.

=cut

sub _csv_line {
    my ($l) = @_;
    my @f;
    while ($l =~ /\G(?:"((?:[^"]|"")*)"|([^,]*))(,|\z)/g) {
        my ($v, $quoted, $sep) = (defined $1 ? $1 : $2, defined $1, $3);
        $v =~ s/""/"/g if $quoted;
        push @f, $v;
        last if $sep eq '';
    }
    return @f;
}

sub _rows {
    my ($file) = @_;
    my $fh = $file =~ /\.gz\z/ ? IO::Uncompress::Gunzip->new($file) : do { open(my $f, '<', $file) or die "cannot read $file: $!\n"; $f };
    $fh or die "cannot read $file: $GunzipError\n";
    return sub {
        while (defined(my $l = <$fh>)) {
            $l =~ s/\r?\n\z//;
            my @f = _csv_line($l);
            return \@f if @f >= 3;
        }
        return;
    };
}

sub build {
    my (%a) = @_;
    my $dir = $a{dir};
    mkdir $dir unless -d $dir;
    my %n = (country => 0, asn => 0);
    my %out;
    my %orgs;
    for my $kind (qw(country asn)) {
        my %fh;
        for my $fam (4, 6) {
            my $f = "$dir/$kind$fam.bin.new";
            open($fh{$fam}, '>:raw', $f) or die "cannot write $f: $!\n";
        }
        my $next = _rows($a{$kind});
        my %last = (4 => '', 6 => '');
        while (my $r = $next->()) {
            my ($s, $e, $v, $org) = @$r;
            my ($fam, $sb) = _bin($s) or next;
            my (undef, $eb) = _bin($e) or next;
            die "$kind data is not in ascending order near $s\n" if $sb lt $last{$fam};
            $last{$fam} = $sb;
            if ($kind eq 'country') { $v = sprintf '%-2.2s', $v; $v = '--' if $v !~ /\A[A-Za-z]{2}\z/ }
            else {
                $v =~ /\A\d+\z/ or next;
                $orgs{$v} //= $org if defined $org && length $org;
                $v = pack 'N', $v;
            }
            print { $fh{$fam} } $sb, $eb, $v;
            $n{$kind}++;
        }
        close $_ or die "write failed: $!\n" for values %fh;
    }
    die "country data has only $n{country} rows -- refusing to install it\n" if $n{country} < ($a{min_rows} // 1000);
    open(my $o, '>:raw', "$dir/asn_org.tsv.new") or die "cannot write asn_org.tsv.new: $!\n";
    for my $asn (sort { $a <=> $b } keys %orgs) { (my $org = $orgs{$asn}) =~ s/[\t\r\n]+/ /g; print {$o} "$asn\t$org\n" }
    close $o or die "write failed: $!\n";
    for my $f (qw(country4.bin country6.bin asn4.bin asn6.bin asn_org.tsv)) {
        rename "$dir/$f.new", "$dir/$f" or die "cannot install $f: $!\n";
    }
    return \%n;
}

1;
