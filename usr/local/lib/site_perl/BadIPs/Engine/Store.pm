package BadIPs::Engine::Store;

# ============================================================================
# The shared ban list (bad-ips 4.0): one PostgreSQL schema, two tables.
#
#   jailed_ips  one row per (address, reporting host); the 3.x table shape,
#               so a legacy host pointed at it still works
#   exemptions  "do not block this address until ..." (written by unban)
#
# Times are epoch seconds (bigint), as in 3.x.
#
# A database problem is never fatal: every call returns undef on failure,
# the caller keeps its data, and the next connection attempt waits with
# backoff (5 s doubling to 60 s). 3.x gave up after five tries and stayed
# disconnected until a reload.
# ============================================================================

use strict;
use warnings;

use DBI;

sub new {
    my ($class, %a) = @_;
    return bless {
        db       => $a{db},          # { host port name user password sslmode schema }
        host     => $a{host},        # this host's name, stored as originating_server
        log      => $a{log},
        dbh      => undef,
        retry_at => 0,
        backoff  => 5,
        last_ok  => 0,
        last_err => '',
        connect  => $a{connect},     # injectable for tests: sub { DBI handle or die }
    }, $class;
}

sub _log { my ($self, $lvl, $m) = @_; $self->{log}->$lvl($m) if $self->{log} }

sub status {
    my ($self) = @_;
    return $self->{dbh} ? 'connected' : ($self->{last_err} ? "down: $self->{last_err}" : 'not connected');
}

sub _connect {
    my ($self) = @_;
    return $self->{connect}->() if $self->{connect};
    my $d = $self->{db};
    my $dsn = sprintf 'dbi:Pg:dbname=%s;host=%s;port=%d;sslmode=%s;connect_timeout=5;application_name=bad_ips',
        $d->{name}, $d->{host}, $d->{port}, $d->{sslmode} // 'prefer';
    my $dbh = DBI->connect($dsn, $d->{user}, $d->{password},
        { RaiseError => 1, PrintError => 0, AutoCommit => 1 }) or die $DBI::errstr;
    $dbh->do('SET statement_timeout = 5000');
    $dbh->do('SET search_path TO ' . $dbh->quote_identifier($d->{schema})) if $d->{schema};
    return $dbh;
}

=head2 dbh($now)

A live handle, or undef while the database is unreachable (in which case
it is not retried before the backoff runs out).

=cut

sub dbh {
    my ($self, $now) = @_;
    $now //= time;
    if ($self->{dbh}) {
        # Re-check a handle that has been idle a while; a pgbouncer or
        # Patroni failover drops it without telling us.
        return $self->{dbh} if $now - $self->{last_ok} < 60 || eval { $self->{dbh}->ping };
        $self->{dbh} = undef;
    }
    return undef if $now < $self->{retry_at};
    my $dbh = eval { $self->_connect };
    unless ($dbh) {
        $self->_fail($now, $@);
        return undef;
    }
    # Say WHERE, the first time and after every outage: a node reporting to
    # the wrong database must be visible in its log from the first minute.
    if ($self->{last_err} || !$self->{ever_ok}) {
        my $d = $self->{db} || {};
        $self->_log(info => sprintf 'shared ban list: %s %s@%s:%s/%s', ($self->{ever_ok} ? 'connected again to' : 'connected to'),
            map { $_ // '?' } @{$d}{qw(user host port name)});
    }
    @{$self}{qw(dbh backoff last_ok last_err ever_ok)} = ($dbh, 5, $now, '', 1);
    return $dbh;
}

sub _fail {
    my ($self, $now, $err) = @_;
    ($err //= 'unknown error') =~ s/\s+\z//;
    $err =~ s/ at \S+ line \d+\.?\z//;
    $self->_log(warn => "shared ban list: $err (retrying in $self->{backoff}s)")
        if $err ne $self->{last_err};
    @{$self}{qw(dbh retry_at last_err)} = (undef, $now + $self->{backoff}, $err);
    $self->{backoff} = $self->{backoff} * 2 > 60 ? 60 : $self->{backoff} * 2;
}

# Runs $code->($dbh) with error handling. Returns its result, or undef.
sub _do {
    my ($self, $now, $code) = @_;
    my $dbh = $self->dbh($now) or return undef;
    my @r = eval { $code->($dbh) };
    if ($@) {
        my $e = $@;
        eval { $dbh->rollback unless $dbh->{AutoCommit} };
        $self->_fail($now, $e);
        return undef;
    }
    $self->{last_ok} = $now;
    return wantarray ? @r : $r[0];
}

my $UPSERT = <<'SQL';
INSERT INTO jailed_ips (ip, originating_server, originating_service, detector_name, pattern_matched,
                        matched_log_line, first_blocked_at, last_seen_at, expires_at, block_count)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
ON CONFLICT (ip, originating_server) DO UPDATE SET
    originating_service = EXCLUDED.originating_service,
    detector_name       = EXCLUDED.detector_name,
    pattern_matched     = EXCLUDED.pattern_matched,
    matched_log_line    = EXCLUDED.matched_log_line,
    last_seen_at        = GREATEST(jailed_ips.last_seen_at, EXCLUDED.last_seen_at),
    expires_at          = GREATEST(jailed_ips.expires_at, EXCLUDED.expires_at),
    block_count         = jailed_ips.block_count + 1
SQL

=head2 push_detections(\@detections, $now)

Writes this host's detections in one transaction. A re-ban keeps the later
end time, so a 1-hour ban can never cut short a 7-day one. Returns the
count written, or undef (nothing written) on failure.

=cut

sub push_detections {
    my ($self, $dets, $now) = @_;
    return 0 unless @$dets;
    return $self->_do($now, sub {
        my ($dbh) = @_;
        $dbh->begin_work;
        my $sth = $dbh->prepare_cached($UPSERT);
        for my $d (@$dets) {
            my $evidence = join("\n", @{ $d->{lines} || [] });
            $evidence = substr($evidence, 0, 4000) if length $evidence > 4000;
            $sth->execute($d->{ip}, $self->{host}, $d->{service}, $d->{rule},
                sprintf('%s hit%s in %ds', $d->{hits}, $d->{hits} == 1 ? '' : 's', $d->{last} - $d->{first}),
                $evidence, $d->{first}, $d->{last}, $d->{expires});
        }
        $dbh->commit;
        return scalar @$dets;
    });
}

=head2 load_active($now)

{ address => expires } for every active ban from any host, minus
exemptions; undef if the database is unreachable.

=cut

sub load_active {
    my ($self, $now) = @_;
    return $self->_do($now, sub {
        my ($dbh) = @_;
        my $rows = $dbh->selectall_arrayref(<<'SQL', undef, $now, $now);
SELECT host(j.ip), max(j.expires_at)
  FROM jailed_ips j
 WHERE j.expires_at > ?
   AND NOT EXISTS (SELECT 1 FROM exemptions e WHERE e.ip >>= j.ip AND e.until_at > ?)
 GROUP BY j.ip
SQL
        return { map { $_->[0] => $_->[1] + 0 } @$rows };
    });
}

=head2 unlocated($now, $limit)

Addresses with an active ban and no row in ip_geo yet (an arrayref, at most
$limit); undef if the database is unreachable or the table is not there yet.

=cut

sub unlocated {
    my ($self, $now, $limit) = @_;
    return $self->_do($now, sub {
        my ($dbh) = @_;
        my $rows = $dbh->selectcol_arrayref(<<'SQL', undef, $now, $limit);
SELECT DISTINCT host(j.ip)
  FROM jailed_ips j
 WHERE j.expires_at > ?
   AND NOT EXISTS (SELECT 1 FROM ip_geo g WHERE g.ip = j.ip)
 LIMIT ?
SQL
        return $rows;
    });
}

=head2 save_geo(\@rows, $now)

Each row is [address, country, asn, org] (any of the last three may be undef:
"looked up, not found" is also an answer, so it is not asked again).
Returns the count written, or undef.

=cut

sub save_geo {
    my ($self, $rows, $now) = @_;
    return 0 unless @$rows;
    return $self->_do($now, sub {
        my ($dbh) = @_;
        $dbh->begin_work;
        my $sth = $dbh->prepare_cached(<<'SQL');
INSERT INTO ip_geo (ip, country, asn, org, looked_up_at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (ip) DO UPDATE SET country = EXCLUDED.country, asn = EXCLUDED.asn,
                               org = EXCLUDED.org, looked_up_at = EXCLUDED.looked_up_at
SQL
        $sth->execute(@$_, $now) for @$rows;
        $dbh->commit;
        return scalar @$rows;
    });
}

=head2 load_exemptions($now)

{ address-or-network => until } for exemptions still running.

=cut

sub load_exemptions {
    my ($self, $now) = @_;
    return $self->_do($now, sub {
        my ($dbh) = @_;
        my $rows = $dbh->selectall_arrayref(
            'SELECT ip::text, max(until_at) FROM exemptions WHERE until_at > ? GROUP BY ip', undef, $now);
        my %e;
        for (@$rows) { (my $k = $_->[0]) =~ s{/(?:32|128)\z}{}; $e{$k} = $_->[1] + 0 }
        return \%e;
    });
}

=head2 unban($ip, by => ..., reason => ..., hours => N, now => ...)

Ends every active ban on the address and adds an exemption for N hours, so
the next matching log line does not ban it straight back. Returns the
number of bans ended, or undef on failure.

=cut

sub unban {
    my ($self, $ip, %a) = @_;
    my $now = $a{now} // time;
    return $self->_do($now, sub {
        my ($dbh) = @_;
        $dbh->begin_work;
        my $n = $dbh->do('UPDATE jailed_ips SET expires_at = ? WHERE ip = ? AND expires_at > ?', undef, $now, $ip, $now);
        $dbh->do('INSERT INTO exemptions (ip, until_at, reason, created_by, created_at) VALUES (?, ?, ?, ?, ?)',
            undef, $ip, $now + 3600 * ($a{hours} // 24), $a{reason} // 'manual unban', $a{by} // 'unknown', $now);
        $dbh->commit;
        return $n eq '0E0' ? 0 : $n + 0;
    });
}

=head2 ban($ip, seconds => N, reason => ..., by => ..., now => ...)

A manual ban, recorded like a detection from this host.

=cut

sub ban {
    my ($self, $ip, %a) = @_;
    my $now = $a{now} // time;
    return $self->_do($now, sub {
        my ($dbh) = @_;
        # End (not delete) any exemption, so `why` keeps the history.
        $dbh->do('UPDATE exemptions SET until_at = ? WHERE ip = ? AND until_at > ?', undef, $now, $ip, $now);
        $dbh->do($UPSERT, undef, $ip, $self->{host}, 'manual', 'manual', $a{reason} // 'manual ban',
            sprintf('banned by %s', $a{by} // 'unknown'), $now, $now, $now + $a{seconds});
        return 1;
    });
}

=head2 list($now, limit => N)

Active bans, newest first: [ { ip, expires, servers, rules, last_seen, total } ].
Every row carries C<total>, the number of active bans altogether, so a
limited list can say how many it left out.

=cut

sub list {
    my ($self, $now, %a) = @_;
    return $self->_do($now, sub {
        my ($dbh) = @_;
        # count(*) OVER () runs after GROUP BY and before LIMIT: the number of
        # banned addresses, not of rows shown.
        return $dbh->selectall_arrayref(<<'SQL', { Slice => {} }, $now, $a{limit} // 1000);
SELECT host(ip) AS ip, max(expires_at) AS expires, max(last_seen_at) AS last_seen,
       string_agg(DISTINCT originating_server, ',') AS servers,
       string_agg(DISTINCT detector_name, ',') AS rules,
       count(*) OVER () AS total
  FROM jailed_ips WHERE expires_at > ?
 GROUP BY ip ORDER BY max(last_seen_at) DESC LIMIT ?
SQL
    });
}

=head2 why($ip, $now)

Everything the list holds about one address: { bans => [...], exemptions => [...] }.

=cut

sub why {
    my ($self, $ip, $now) = @_;
    return $self->_do($now, sub {
        my ($dbh) = @_;
        my $bans = $dbh->selectall_arrayref(<<'SQL', { Slice => {} }, $ip);
SELECT originating_server AS server, originating_service AS service, detector_name AS rule,
       pattern_matched AS summary, matched_log_line AS evidence, first_blocked_at AS first,
       last_seen_at AS last_seen, expires_at AS expires, block_count AS times
  FROM jailed_ips WHERE ip = ? ORDER BY last_seen_at DESC LIMIT 20
SQL
        my $ex = $dbh->selectall_arrayref(<<'SQL', { Slice => {} }, $ip);
SELECT ip::text AS ip, until_at AS until, reason, created_by AS by, created_at AS at
  FROM exemptions WHERE ip >>= ? ORDER BY created_at DESC LIMIT 10
SQL
        return { bans => $bans, exemptions => $ex };
    });
}

1;
