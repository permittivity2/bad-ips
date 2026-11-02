#!/usr/bin/perl
# Log sources (BadIPs::Engine::Source::File / ::Journal).
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../usr/local/lib/site_perl";
use File::Temp qw(tempdir);

use BadIPs::Engine::Source;

my $dir = tempdir(CLEANUP => 1);
sub append { my ($f, $t) = @_; open my $fh, '>>', $f or die; print {$fh} $t; close $fh }
sub lines  { map { $_->[0] } @_ }

# --- first start reads back only the tail, skipping the partial first line --
my $log = "$dir/a.log";
append($log, join('', map { sprintf "line %03d\n", $_ } 1 .. 100));   # 9 bytes each
my $s = BadIPs::Engine::Source::File->new(path => $log, backread => 40);
my @got = lines($s->read);
is_deeply \@got, [ 'line 097', 'line 098', 'line 099', 'line 100' ],
    'first start reads back only `backread` bytes and drops the partial first line';

# --- only new lines after that, and a partial line waits for its newline -----
append($log, "line 101\nline 1");
is_deeply [ lines($s->read) ], ['line 101'], 'new complete lines only';
append($log, "02\n");
is_deeply [ lines($s->read) ], ['line 102'], 'a partial line is held until its newline';
is_deeply [ $s->read ], [], 'nothing new, nothing returned';

# --- resume from a saved position ---------------------------------------------
append($log, "line 103\n");
my $pos = $s->position;
my $s2 = BadIPs::Engine::Source::File->new(path => $log, saved => $pos, backread => 40);
is_deeply [ lines($s2->read) ], ['line 103'], 'a restart resumes exactly where the last run stopped';

my $s3 = BadIPs::Engine::Source::File->new(path => $log, saved => { ino => -5, pos => 0 }, backread => 20);
my @tail = lines($s3->read);
ok @tail <= 2 && $tail[-1] eq 'line 103', 'a saved position for a different file is ignored (tail read instead)';

# --- rotation by rename --------------------------------------------------------
append($log, "line 104\n");
rename $log, "$log.1" or die;
append("$log.1", "line 105 written to the old file before the HUP\n");
append($log, "new 1\nnew 2\n");
is_deeply [ lines($s->read) ],
    [ 'line 103', 'line 104', 'line 105 written to the old file before the HUP', 'new 1', 'new 2' ],
    'rotation: drains the old file, then reads the new one from its start';
append($log, "new 3\n");
is_deeply [ lines($s->read) ], ['new 3'], 'and keeps following the new file';

# --- copytruncate ---------------------------------------------------------------
open my $tr, '>', $log or die; close $tr;    # truncate in place
append($log, "after truncate\n");
is_deeply [ lines($s->read) ], ['after truncate'], 'truncation in place restarts from the beginning';

# --- a file that does not exist yet ---------------------------------------------
my $later = BadIPs::Engine::Source::File->new(path => "$dir/later.log");
is_deeply [ $later->read ], [], 'a missing file yields nothing';
append("$dir/later.log", "first\nsecond\n");
is_deeply [ lines($later->read) ], [ 'first', 'second' ], 'and is read from its start once it appears';

# --- CRLF and bytes that are not UTF-8 ------------------------------------------
append("$dir/later.log", "crlf line\r\n\xff\xfe raw\n");
is_deeply [ lines($later->read) ], [ 'crlf line', "\xff\xfe raw" ], 'CR stripped, raw bytes passed through';

# --- journal --------------------------------------------------------------------
my $fake = "$dir/journalctl";
open my $jf, '>', $fake or die;
print {$jf} <<"SH";
#!/bin/sh
echo "\$@" > "$dir/journal-args"
cat <<'JSON'
{"__CURSOR":"s=abc;i=1","__REALTIME_TIMESTAMP":"1762119270123456","MESSAGE":"Failed password for root from 203.0.113.70 port 22 ssh2"}
{"__CURSOR":"s=abc;i=2","__REALTIME_TIMESTAMP":"1762119271000000","MESSAGE":[104,105]}
JSON
SH
close $jf;
chmod 0755, $fake;

my $j = BadIPs::Engine::Source::Journal->new(unit => 'ssh', journalctl => $fake, interval => 0);
my @e = $j->read(undef, 1762119300);
is_deeply \@e, [ [ 'Failed password for root from 203.0.113.70 port 22 ssh2', 1762119270 ], [ 'hi', 1762119271 ] ],
    'journal entries carry their own time; byte-array messages are decoded';
like do { open my $a, '<', "$dir/journal-args"; local $/; <$a> }, qr/--since \@1762118700/, 'first read looks back one window';
is_deeply $j->position, { cursor => 's=abc;i=2' }, 'cursor saved';
$j->read(undef, 1762119400);
like do { open my $a, '<', "$dir/journal-args"; local $/; <$a> }, qr/--after-cursor s=abc;i=2/, 'later reads resume from the cursor';

done_testing;
