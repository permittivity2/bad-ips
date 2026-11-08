package BadIPs::Engine;

# ============================================================================
# bad-ips 4.0 role mode: the daemon.
#
#   role = report   watch logs, report detections to the shared ban list;
#                   never touch the local firewall.
#   role = block    the same, plus: read the whole shared list, add the
#                   public blocklist feeds, and keep the kernel's
#                   `inet badips` table equal to it (BadIPs::Engine::Firewall).
#   role = off      do nothing (the package installs the unit disabled).
#   dry_run = 1     watch mode: everything except touching the firewall.
#
# One thread, one loop. Each pass reads new log lines (bounded), then, when
# due: pushes queued detections, refreshes exemptions, reconciles the
# firewall, refreshes feeds, saves log positions and the queue, and logs a
# heartbeat. A database outage only delays sharing: detections queue
# (bounded, and saved to state_dir so a restart loses none) and the block
# role keeps enforcing its last good list plus its own detections.
#
# (3.x ran one thread per job; role mode does not need any of them, and
# leaves the legacy daemon untouched for hosts without a role.)
# ============================================================================

use strict;
use warnings;

use JSON ();
use POSIX qw(strftime);
use Log::Log4perl qw(get_logger);

use BadIPs::Engine::Config;
use BadIPs::Engine::Net qw(parse_cidr overlaps);
use BadIPs::Engine::Rules;
use BadIPs::Engine::Source;
use BadIPs::Engine::Store;
use BadIPs::Engine::Firewall;
use BadIPs::Engine::Feed;
use BadIPs::Engine::Metrics;
use BadIPs::Engine::Geo;

sub new {
    my ($class, %a) = @_;
    my $self = bless {
        conf_main => $a{conf_main} // '/usr/local/etc/badips.conf',
        conf_dir  => $a{conf_dir}  // '/usr/local/etc/badips.d',
        host      => $a{host},
        force_dry => $a{dry_run} ? 1 : 0,
        log       => $a{log} // get_logger('BadIPs::Engine'),
        runner    => $a{runner},          # tests: firewall helper stand-in
        store_connect => $a{store_connect},
        running   => 1,
        reload    => 0,
        queue     => [],
        own       => {},                  # ip => { expires, pushed }
        exempt    => {},                  # addr-or-net => until
        sources   => {},                  # path => source object (kept across reloads)
        stats     => { map { $_ => 0 } qw(lines matches never_skipped exempt_skipped detections pushed dropped located) },
        next      => {},
        by_rule   => {},
    }, $class;
    return $self;
}

sub logger { $_[0]{log} }

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

sub load_config {
    my ($self) = @_;
    my ($s, $err, $notes) = BadIPs::Engine::Config::load(
        conf_main => $self->{conf_main}, conf_dir => $self->{conf_dir}, host => $self->{host});
    $s->{dry_run} = 1 if $self->{force_dry};
    return ($s, $err, $notes);
}

sub _setup {
    my ($self, $s) = @_;
    my $old = $self->{s};
    $self->{s} = $s;

    # rules, grouped by source; counters kept for rules that did not change
    my (%by_src, %counters);
    for my $r (@{ $s->{rules} }) {
        my $c = $self->{counters}{ $r->{name} };
        $counters{ $r->{name} } = ($c && _same_rule($c->{rule}, $r)) ? $c : BadIPs::Engine::Counter->new(rule => $r);
        $counters{ $r->{name} }{rule} = $r;
        for my $src ($r->{journal} ? ("journal:$r->{journal}") : @{ $r->{files} }) {
            push @{ $by_src{$src} }, $r;
        }
    }
    $self->{counters} = \%counters;
    $self->{by_src}   = \%by_src;

    # sources: keep the open ones, add new ones from saved positions
    my $saved = $self->_load_positions;
    my %src;
    for my $path (keys %by_src) {
        $src{$path} = $self->{sources}{$path} // do {
            $path =~ /\Ajournal:(.+)/
                ? BadIPs::Engine::Source::Journal->new(unit => $1, saved => $saved->{$path},
                                                       lookback => _max_window($by_src{$path}))
                : BadIPs::Engine::Source::File->new(path => $path, saved => $saved->{$path},
                                                    backread => $s->{backread_bytes});
        };
    }
    $self->{sources} = \%src;

    # shared list
    my $db_same = $old && $old->{db} && $s->{db} && JSON->new->canonical->encode($old->{db}) eq JSON->new->canonical->encode($s->{db});
    $self->{store} = !$s->{db} ? undef
                   : $db_same  ? $self->{store}
                   : BadIPs::Engine::Store->new(db => $s->{db}, host => $s->{host}, log => $self->{log},
                                                connect => $self->{store_connect});

    # firewall: block role only. Any other host (report, or watch mode) must
    # block nothing, so a table left by an earlier role or run is removed.
    if ($s->{role} eq 'block' && !$s->{dry_run}) {
        $self->{firewall} = BadIPs::Engine::Firewall->new(
            ifaces => $s->{block_interfaces}, dns_accept => $s->{dns_accept}, never => $s->{never},
            log => $self->{log}, runner => $self->{runner});
    }
    else {
        $self->{firewall} = undef;
        BadIPs::Engine::Firewall->new(never => $s->{never}, log => $self->{log}, runner => $self->{runner})
            ->remove_if_present if $s->{role} ne 'off';
    }
    # feeds: block role only (in watch mode too, to say what would be blocked)
    if ($s->{role} eq 'block') {
        $self->{feeds} = [ map {
            my $f = BadIPs::Engine::Feed->new(%$_, cache_dir => $s->{cache_dir}, log => $self->{log});
            $f->load_cache;
            $f;
        } @{ $s->{feeds} } ];
    }
    else {
        $self->{feeds} = [];
    }
    $self->{next}{reconcile} = 0;    # reconcile straight away after (re)configuring
}

sub _same_rule {
    my ($a, $b) = @_;
    return 0 unless $a && $b;
    return $a->{re} eq $b->{re} && $a->{count} == $b->{count} && $a->{window} == $b->{window} && $a->{ban} == $b->{ban};
}

sub _max_window { my $m = 0; for (@{ $_[0] }) { $m = $_->{window} if $_->{window} > $m } return $m || 600 }

# --------------------------------------------------------------------------
# positions, and the queue of detections not yet shared
# --------------------------------------------------------------------------

sub _positions_file { "$_[0]{s}{state_dir}/engine-positions.json" }
sub _queue_file     { "$_[0]{s}{state_dir}/engine-queue.json" }

sub _load_positions {
    my ($self) = @_;
    my $f = $self->_positions_file;
    open(my $fh, '<', $f) or return {};
    local $/;
    return eval { JSON->new->decode(scalar <$fh>) } || {};
}

sub save_positions {
    my ($self) = @_;
    my %p;
    for my $path (keys %{ $self->{sources} }) {
        my $pos = $self->{sources}{$path}->position or next;
        $p{$path} = $pos;
    }
    my $text = JSON->new->canonical->encode(\%p);
    return if defined $self->{saved_positions} && $self->{saved_positions} eq $text;
    my $f = $self->_positions_file;
    if (open(my $fh, '>', "$f.tmp")) {
        print {$fh} $text;
        close $fh;
        rename "$f.tmp", $f and $self->{saved_positions} = $text;
    }
}

=head2 load_queue($now)

The detections that were still waiting for the shared list when the daemon
last saved (every few seconds, and on stop), minus those whose ban has run
out. Log positions move on as lines are read, so without this a restart
during a database outage lost every detection the outage had held back.
Called once, at start: a reload keeps the queue it has in memory.

=cut

sub load_queue {
    my ($self, $now) = @_;
    return unless $self->{store};
    my $f = $self->_queue_file;
    open(my $fh, '<', $f) or return;
    local $/;
    my $saved = eval { JSON->new->utf8->decode(scalar <$fh>) };
    return unless ref $saved eq 'ARRAY' && @$saved;
    my @keep = grep { ref $_ eq 'HASH' && defined $_->{ip} && ($_->{expires} // 0) > $now } @$saved;
    my $over = @keep - $self->{s}{queue_max};
    splice(@keep, 0, $over) if $over > 0;    # beyond the bound the oldest go, as when they were queued
    push @{ $self->{queue} }, @keep;
    if ($self->{s}{role} eq 'block') {
        # our own finds, not yet on the list: enforce them now, as before the restart
        for my $d (@keep) {
            my $o = $self->{own}{ $d->{ip} };
            $self->{own}{ $d->{ip} } = { expires => $d->{expires}, pushed => 0 } if !$o || $o->{expires} < $d->{expires};
        }
        $self->{next}{reconcile} = 0 if @keep;
    }
    $self->logger->info(sprintf 'restored %d detection%s not yet shared (%d expired meanwhile, dropped) from %s',
        scalar @keep, (@keep == 1 ? '' : 's'), @$saved - @keep, $f);
}

=head2 save_queue

Writes the queue to state_dir when it has changed since the last save; an
empty queue removes the file.

=cut

sub save_queue {
    my ($self) = @_;
    my $f = $self->_queue_file;
    my $text = @{ $self->{queue} } ? JSON->new->canonical->utf8->encode($self->{queue}) : '';
    return if defined $self->{saved_queue} && $self->{saved_queue} eq $text;
    if ($text eq '') {
        unlink $f;
        $self->{saved_queue} = '';
        return;
    }
    if (open(my $fh, '>', "$f.tmp")) {
        print {$fh} $text;
        close $fh;
        rename "$f.tmp", $f and $self->{saved_queue} = $text;
    }
}

# --------------------------------------------------------------------------
# detection
# --------------------------------------------------------------------------

sub _exempt {
    my ($self, $ip, $now) = @_;
    my $e = $self->{exempt};
    return 1 if ($e->{$ip} // 0) > $now;
    my $p;
    for my $k (keys %$e) {
        next unless $k =~ m{/} && $e->{$k} > $now;
        $p //= parse_cidr($ip);
        return 1 if overlaps(parse_cidr($k), $p);
    }
    return 0;
}

sub handle_line {
    my ($self, $path, $item, $now) = @_;
    my ($line, $ts) = @$item;
    for my $r (@{ $self->{by_src}{$path} || [] }) {
        my ($ip, $w) = BadIPs::Engine::Rules::match_line($r, $line) or next;
        $self->{stats}{matches}++;
        if ($self->{s}{never}->conflict($ip)) { $self->{stats}{never_skipped}++; next }
        if ($self->_exempt($ip, $now))        { $self->{stats}{exempt_skipped}++; next }
        my $t = $ts // BadIPs::Engine::Rules::line_time($line, $r->{format}, $now) // $now;
        my $d = $self->{counters}{ $r->{name} }->observe($ip, $t, $w, $line) or next;
        next if $d->{expires} <= $now;    # an old burst re-read after a restart: already over
        $self->_detected($d, $now);
    }
}

sub _detected {
    my ($self, $d, $now) = @_;
    $self->{stats}{detections}++;
    $self->{by_rule}{ $d->{rule} }++;
    $self->logger->info(sprintf 'detected %s: %s (%d hits) -> ban until %s',
        $d->{ip}, $d->{rule}, $d->{hits}, strftime('%Y-%m-%d %H:%M:%S', localtime $d->{expires}));
    if ($self->{store}) {
        push @{ $self->{queue} }, $d;
        if (@{ $self->{queue} } > $self->{s}{queue_max}) {
            shift @{ $self->{queue} };
            $self->{stats}{dropped}++;
        }
    }
    if ($self->{s}{role} eq 'block') {
        my $o = $self->{own}{ $d->{ip} };
        if (!$o || $o->{expires} < $d->{expires}) {
            $self->{own}{ $d->{ip} } = { expires => $d->{expires}, pushed => 0 };
            $self->{next}{reconcile} = 0;    # block it in this pass, not at the next reconcile
        }
    }
}

sub read_sources {
    my ($self, $now) = @_;
    my $budget = $self->{s}{max_read_bytes};
    for my $path (sort keys %{ $self->{sources} }) {
        for my $item ($self->{sources}{$path}->read($budget, $now)) {
            $self->{stats}{lines}++;
            $self->handle_line($path, $item, $now);
        }
    }
}

# --------------------------------------------------------------------------
# shared list, exemptions, firewall, feeds
# --------------------------------------------------------------------------

sub push_queue {
    my ($self, $now) = @_;
    my $q = $self->{queue};
    return unless @$q && $self->{store};
    my @batch = splice(@$q, 0, 500);
    my $n = $self->{store}->push_detections(\@batch, $now);
    if (defined $n) {
        $self->{stats}{pushed} += $n;
        for my $d (@batch) { $self->{own}{ $d->{ip} }{pushed} = 1 if $self->{own}{ $d->{ip} } }
        $self->{next}{reconcile} = 0 if $self->{s}{role} eq 'block';   # block it now, not in 30 s
    }
    else {
        unshift @$q, @batch;    # keep them; the store backs off on its own
    }
}

sub refresh_exemptions {
    my ($self, $now) = @_;
    return unless $self->{store};
    my $e = $self->{store}->load_exemptions($now);
    $self->{exempt} = $e if $e;
}

sub desired_bans {
    my ($self, $now) = @_;
    my $active;
    if ($self->{store}) {
        $active = $self->{store}->load_active($now);
        if ($active) { $self->{last_active} = $active } else { $active = $self->{last_active} || {} }
    }
    my $db_live = $self->{store} && $self->{store}{dbh} ? 1 : 0;
    my %b = map { $_ => $active->{$_} } grep { $active->{$_} > $now } keys %{ $active || {} };
    for my $ip (keys %{ $self->{own} }) {
        my $o = $self->{own}{$ip};
        if ($o->{expires} <= $now) { delete $self->{own}{$ip}; next }
        # Once the shared list has it, the list decides (so `unban` works);
        # until then, or while the database is down, our own detection counts.
        next if $o->{pushed} && $db_live;
        next if $self->_exempt($ip, $now);
        $b{$ip} = $o->{expires} if !$b{$ip} || $b{$ip} < $o->{expires};
    }
    for my $ip (keys %b) {
        if (my $c = $self->{s}{never}->conflict($ip)) {
            delete $b{$ip};
            unless ($self->{warned_never}{$ip}++) {
                $self->{never_refused}++;
                $self->logger->warn("refusing to block never-block address $ip (matches $c)");
            }
        }
    }
    return \%b;
}

sub desired_feed {
    my ($self) = @_;
    my @out;
    for my $f (@{ $self->{feeds} || [] }) {
        for my $c (@{ $f->entries }) {
            if (my $n = $self->{s}{never}->conflict($c)) {
                unless ($self->{warned_never}{$c}++) {
                    $self->{never_refused}++;
                    $self->logger->warn(sprintf 'feed %s: refusing %s (overlaps never-block %s)', $f->name, $c, $n);
                }
                next;
            }
            push @out, $c;
        }
    }
    return \@out;
}

sub reconcile {
    my ($self, $now) = @_;
    my $bans = $self->desired_bans($now);
    my $feed = $self->desired_feed;
    $self->{last_counts} = { bans => scalar keys %$bans, feed => scalar @$feed };
    unless ($self->{firewall}) {
        my $sig = "$self->{last_counts}{bans}/$self->{last_counts}{feed}";
        $self->logger->info("watch mode: would block $self->{last_counts}{bans} addresses and $self->{last_counts}{feed} feed ranges")
            if ($self->{watch_sig} // '') ne $sig;
        $self->{watch_sig} = $sig;
        $self->{last_sync} = $now;
        return { ok => 1, watch => 1 };
    }
    my $r = $self->{firewall}->reconcile(bans => $bans, feed => $feed, now => $now);
    if (!$r->{ok}) {
        $self->logger->error("firewall: $r->{error}") if ($self->{last_fw_err} // '') ne $r->{error};
        $self->{last_fw_err} = $r->{error};
    }
    else {
        $self->logger->info("firewall: blocked $r->{added} new, unblocked $r->{removed}"
            . ($r->{extended} ? ", extended $r->{extended}" : '') . ($r->{feed_reloaded} ? ', feed reloaded' : ''))
            if !$r->{replaced} && ($r->{added} || $r->{removed} || $r->{extended});
        $self->logger->info('firewall: recovered') if $self->{last_fw_err};
        $self->{last_fw_err} = undef;
        $self->{last_sync} = $now;
        $self->{fw_rebuilds}++ if $r->{replaced};
    }
    $self->{last_fw} = $r;
    return $r;
}

# Country and network owner for the addresses on the shared list (block role
# only; one host does it for everyone). A few at a time, so a big new list is
# worked through over several passes without holding up the loop.
sub locate {
    my ($self, $now) = @_;
    return unless $self->{store};
    my $geo = $self->{geo} //= BadIPs::Engine::Geo->new(dir => $self->{s}{geo_dir});
    unless ($geo->available) {
        $self->logger->info("geo: no data in $self->{s}{geo_dir} yet (bad_ips-geo.timer fetches it); bans carry no country until then")
            unless $self->{geo_warned}++;
        return;
    }
    my $todo = $self->{store}->unlocated($now, 200) or return;
    return unless @$todo;
    my @rows;
    for my $ip (@$todo) {
        my $g = $geo->lookup($ip);
        push @rows, [ $ip, $g->{country}, $g->{asn}, $g->{org} ];
    }
    my $n = $self->{store}->save_geo(\@rows, $now);
    $self->{stats}{located} += $n if $n;
}

sub refresh_feeds {
    my ($self, $now) = @_;
    my $changed = 0;
    for my $f (@{ $self->{feeds} || [] }) { $changed ||= $f->refresh($now) if $f->due($now) }
    $self->{next}{reconcile} = 0 if $changed;
}

sub heartbeat {
    my ($self) = @_;
    my $s = $self->{stats};
    $self->logger->info(sprintf 'role=%s%s lines=%d matches=%d detections=%d pushed=%d queued=%d dropped=%d never_skipped=%d exempt_skipped=%d%s db=%s',
        $self->{s}{role}, ($self->{s}{dry_run} ? '(watch)' : ''), @{$s}{qw(lines matches detections pushed)},
        scalar @{ $self->{queue} }, @{$s}{qw(dropped never_skipped exempt_skipped)},
        ($self->{last_counts} ? " blocking=$self->{last_counts}{bans}+$self->{last_counts}{feed}feed" : ''),
        ($self->{store} ? $self->{store}->status : 'none'));
}

# --------------------------------------------------------------------------
# the loop
# --------------------------------------------------------------------------

=head2 step($now)

One pass of the loop (exposed for tests).

=cut

sub step {
    my ($self, $now) = @_;
    my $s = $self->{s};
    my $n = $self->{next};
    $self->read_sources($now);
    if ($now >= ($n->{push} // 0))      { $self->push_queue($now);         $n->{push}   = $now + $s->{push_interval} }
    if ($now >= ($n->{exempt} // 0))    { $self->refresh_exemptions($now); $n->{exempt} = $now + $s->{exemption_refresh} }
    if ($s->{role} eq 'block') {
        if ($now >= ($n->{feeds} // 0)) { $self->refresh_feeds($now);      $n->{feeds}  = $now + 600 }
        if ($now >= ($n->{geo} // 0))   { $self->locate($now);            $n->{geo}    = $now + 60 }
        if ($now >= ($n->{reconcile} // 0)) { $self->reconcile($now);      $n->{reconcile} = $now + $s->{reconcile_interval} }
    }
    if ($now >= ($n->{metrics} // 0))   {
        eval { BadIPs::Engine::Metrics::publish($self, $now); 1 } or $self->logger->warn("metrics: $@");
        $n->{metrics} = $now + $s->{metrics_interval};
    }
    if ($now >= ($n->{save} // 0))      { $self->save_positions; $self->save_queue; $n->{save} = $now + 10 }
    if ($now >= ($n->{expire} // 0))    { $_->expire($now) for values %{ $self->{counters} }; $n->{expire} = $now + 60 }
    if ($now >= ($n->{heartbeat} // $now + $s->{heartbeat})) { $self->heartbeat; $n->{heartbeat} = $now + $s->{heartbeat} }
    $n->{heartbeat} //= $now + $s->{heartbeat};
}

sub start {
    my ($self) = @_;
    my ($s, $err, $notes) = $self->load_config;
    if (@$err) {
        $self->logger->error("configuration error: $_") for @$err;
        return 0;
    }
    $self->logger->info("note: $_") for @$notes;
    $self->_setup($s);
    $self->load_queue(time);
    return 1;
}

sub run {
    my ($self) = @_;
    $self->start or return 1;
    my $s = $self->{s};
    if ($s->{role} eq 'off') {
        $self->logger->info('role = off: nothing to do');
        return 0;
    }
    $self->logger->info(sprintf 'bad-ips role mode started: role=%s%s host=%s rules=%d sources=%d database=%s%s',
        $s->{role}, ($s->{dry_run} ? ' (watch mode: the firewall is never touched)' : ''), $s->{host},
        scalar @{ $s->{rules} }, scalar keys %{ $self->{sources} }, ($s->{db} ? "$s->{db}{host}:$s->{db}{port}/$s->{db}{name}" : 'none'),
        (@{ $s->{block_interfaces} } ? " interfaces=@{ $s->{block_interfaces} }" : ''));
    # where the settings that matter came from: a wrong file is visible here
    my $f = $s->{from} || {};
    $self->logger->info(sprintf 'settings from: role %s; never-block %s; database %s',
        $f->{role} // '?', $f->{never_block_cidrs} // '(the built-in floor only)',
        ($s->{db} ? "$s->{db}{user}\@$s->{db}{host}:$s->{db}{port}/$s->{db}{name} from " . ($f->{db_host} // '?') : 'none'));

    local $SIG{TERM} = sub { $self->{running} = 0 };
    local $SIG{INT}  = sub { $self->{running} = 0 };
    local $SIG{HUP}  = sub { $self->{reload} = 1 };

    while ($self->{running}) {
        if ($self->{reload}) {
            $self->{reload} = 0;
            my ($ns, $err, $notes) = $self->load_config;
            if (@$err) {
                $self->logger->error("reload refused, keeping the running configuration: $_") for @$err;
            }
            else {
                $self->logger->info('configuration reloaded');
                $self->logger->info("note: $_") for @$notes;
                $self->{warned_never} = {};
                $self->_setup($ns);
                $s = $self->{s};
                last if $s->{role} eq 'off';
            }
        }
        my $now = time;
        eval { $self->step($now); 1 } or $self->logger->error("loop error (continuing): $@");
        select(undef, undef, undef, $s->{sleep_time}) if $self->{running} && !$self->{reload};
    }
    $self->push_queue(time) if @{ $self->{queue} };
    $self->save_positions;
    $self->save_queue;    # whatever the database did not take is here for the next start
    $self->logger->info('bad-ips role mode stopped');
    return 0;
}

1;
