package BadIPs::Engine::Source;

# ============================================================================
# Log sources for role mode (bad-ips 4.0).
#
# BadIPs::Engine::Source::File follows one log file:
#   * resumes from a saved (inode, offset) when the file is the same one;
#   * otherwise starts near the end and reads back at most `backread` bytes
#     (default 2 MB), never the whole file (mail logs here run to 200+ MB);
#   * survives rotation by rename (drains the old file, then opens the new
#     one from the start) and by copytruncate (size drops below the offset);
#   * holds a partial last line until its newline arrives.
#
# BadIPs::Engine::Source::Journal reads one systemd unit with journalctl,
# resuming from a saved cursor.
#
# Both return items [ $line, $epoch_or_undef ]. File lines carry no time of
# their own here; the rule's line_time() reads it from the text. Journal
# entries carry __REALTIME_TIMESTAMP.
# ============================================================================

use strict;
use warnings;

package BadIPs::Engine::Source::File;

use strict;
use warnings;

sub new {
    my ($class, %a) = @_;
    return bless {
        path     => $a{path},
        backread => $a{backread} // 2 * 1024 * 1024,
        saved    => $a{saved},       # { ino => N, pos => N } from a previous run
        fh       => undef,
        ino      => undef,
        pos      => 0,
        buf      => '',
        skip     => 0,               # drop the first (partial) line after a mid-file start
    }, $class;
}

sub path { $_[0]{path} }

=head2 position

{ ino, pos } for saving: the offset of the first byte not yet returned as
a complete line, so a restart re-reads a held partial line rather than
losing it.

=cut

sub position {
    my ($self) = @_;
    return undef unless defined $self->{ino};
    return { ino => $self->{ino}, pos => $self->{pos} - length($self->{buf}) };
}

sub _open {
    my ($self, $from_start) = @_;
    open(my $fh, '<:raw', $self->{path}) or return 0;
    my @st = stat($fh);
    my ($ino, $size) = ($st[1], $st[7]);
    my $pos;
    if ($from_start) {
        $pos = 0;
    }
    elsif ($self->{saved} && ($self->{saved}{ino} // -1) == $ino && ($self->{saved}{pos} // -1) <= $size) {
        $pos = $self->{saved}{pos};
    }
    else {
        $pos = $size > $self->{backread} ? $size - $self->{backread} : 0;
        $self->{skip} = $pos > 0 ? 1 : 0;
    }
    $self->{saved} = undef;
    sysseek($fh, $pos, 0) or return 0;
    @{$self}{qw(fh ino pos buf)} = ($fh, $ino, $pos, '');
    return 1;
}

=head2 read(max_bytes)

Returns complete new lines (as [line, undef]) read since the last call,
at most about max_bytes worth. Missing files are retried on the next call.

=cut

sub read {
    my ($self, $max) = @_;
    $max //= 8 * 1024 * 1024;
    my @out;
    unless ($self->{fh}) { $self->_open(0) or return () }

    my $budget = $max;
    while ($budget > 0) {
        my $n = sysread($self->{fh}, my $chunk, $budget > 65536 ? 65536 : $budget);
        last unless defined $n;
        if ($n == 0) {
            # At EOF: rotated (new inode at the path) or truncated?
            my @st = stat($self->{path});
            if (!@st) {
                last;    # renamed away and not yet recreated: keep the old handle
            }
            if ($st[1] != $self->{ino}) {
                # Drained the old file; switch to the new one from its start.
                my $keep = $self->{buf};
                close $self->{fh};
                $self->{fh} = undef;
                push @out, [ $keep, undef ] if length $keep;   # unterminated last line of the old file
                $self->_open(1) or last;
                next;
            }
            if ($st[7] < $self->{pos}) {
                sysseek($self->{fh}, 0, 0);
                @{$self}{qw(pos buf skip)} = (0, '', 0);
                next;
            }
            last;
        }
        $self->{pos} += $n;
        $budget      -= $n;
        $self->{buf} .= $chunk;
        while ((my $i = index($self->{buf}, "\n")) >= 0) {
            my $line = substr($self->{buf}, 0, $i);
            substr($self->{buf}, 0, $i + 1, '');
            if ($self->{skip}) { $self->{skip} = 0; next }
            $line =~ s/\r\z//;
            push @out, [ $line, undef ];
        }
    }
    return @out;
}

package BadIPs::Engine::Source::Journal;

use strict;
use warnings;
use JSON ();

sub new {
    my ($class, %a) = @_;
    return bless {
        unit       => $a{unit},
        lookback   => $a{lookback} // 600,
        cursor     => $a{saved} ? $a{saved}{cursor} : undef,
        journalctl => $a{journalctl} // 'journalctl',
        interval   => $a{interval} // 5,
        last_run   => 0,
        json       => JSON->new->allow_nonref,
    }, $class;
}

sub path { 'journal:' . $_[0]{unit} }

sub position { my ($self) = @_; return defined $self->{cursor} ? { cursor => $self->{cursor} } : undef }

sub read {
    my ($self, $max, $now) = @_;
    $now //= time;
    return () if $now - $self->{last_run} < $self->{interval};
    $self->{last_run} = $now;

    my @args = ($self->{journalctl}, '-u', $self->{unit}, '-o', 'json', '--no-pager', '-q', '-n', '20000');
    push @args, defined $self->{cursor} ? ('--after-cursor', $self->{cursor})
                                        : ('--since', '@' . int($now - $self->{lookback}));
    open(my $fh, '-|', @args) or return ();
    my @out;
    while (my $j = <$fh>) {
        my $e = eval { $self->{json}->decode($j) } or next;
        $self->{cursor} = $e->{__CURSOR} if defined $e->{__CURSOR};
        my $msg = $e->{MESSAGE};
        $msg = pack('C*', @$msg) if ref $msg eq 'ARRAY';   # journald sends non-UTF-8 messages as byte arrays
        next unless defined $msg;
        my $ts = defined $e->{__REALTIME_TIMESTAMP} ? int($e->{__REALTIME_TIMESTAMP} / 1_000_000) : undef;
        push @out, [ $msg, $ts ];
    }
    close $fh;
    return @out;
}

1;
