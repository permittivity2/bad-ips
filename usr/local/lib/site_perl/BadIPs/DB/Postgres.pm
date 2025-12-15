package BadIPs::DB::Postgres;

use strict;
use warnings;
use DBI;
use Log::Log4perl qw(get_logger);
use Sys::Hostname;

our $VERSION = '3.3.2';

my $log = get_logger("BadIPs::DB::Postgres");

=head1 NAME

BadIPs::DB::Postgres - PostgreSQL backend for Bad IPs database

=head1 SYNOPSIS

    use BadIPs::DB::Postgres;

    my $pg = BadIPs::DB::Postgres->new(
        db_host     => 'localhost',
        db_port     => 5432,
        db_name     => 'bad_ips',
        db_user     => 'bad_ips',
        db_password => 'password',
        db_ssl_mode => 'prefer',
    );

    my $dbh = $pg->connect();

=head1 DESCRIPTION

BadIPs::DB::Postgres implements the PostgreSQL-specific database operations
for the Bad IPs system.

=head1 METHODS

=head2 new

    my $pg = BadIPs::DB::Postgres->new(%options);

Creates a new PostgreSQL backend instance.

Options:
    db_host     => Database hostname
    db_port     => Database port (default: 5432)
    db_name     => Database name
    db_user     => Database username
    db_password => Database password
    db_ssl_mode => SSL mode (default: prefer)

=cut

sub new {
    my ($class, %args) = @_;

    my $self = {
        db_host     => $args{db_host},
        db_port     => $args{db_port} || 5432,
        db_name     => $args{db_name},
        db_user     => $args{db_user},
        db_password => $args{db_password},
        db_ssl_mode => $args{db_ssl_mode} || 'prefer',
    };

    bless $self, $class;
    return $self;
}

=head2 connect

    my $dbh = $pg->connect();

Establishes a connection to PostgreSQL and returns a DBI handle.

Returns:
    DBI database handle on success, undef on failure.

=cut

sub connect {
    my ($self) = @_;

    return undef unless $self->{db_host} && defined $self->{db_password};

    my $dsn = sprintf(
        "dbi:Pg:dbname=%s;host=%s;port=%s;sslmode=%s",
        $self->{db_name},
        $self->{db_host},
        $self->{db_port},
        $self->{db_ssl_mode}
    );

    my $dbh;
    eval {
        $dbh = DBI->connect(
            $dsn,
            $self->{db_user},
            $self->{db_password},
            {
                AutoCommit     => 1,
                RaiseError     => 1,
                PrintError     => 0,
                pg_enable_utf8 => 1,
            }
        );
    };

    if ($@) {
        $log->error("PostgreSQL connection failed: $@");
        return undef;
    }

    $log->debug("Connected to PostgreSQL at $self->{db_host}:$self->{db_port}/$self->{db_name}");
    return $dbh;
}

=head2 test_connection

    my $ok = $pg->test_connection($dbh);

Tests if a database connection is alive.

Arguments:
    $dbh => DBI database handle

Returns:
    1 if connection is alive, 0 otherwise.

=cut

sub test_connection {
    my ($self, $dbh) = @_;

    return 0 unless $dbh;

    eval {
        $dbh->do("SELECT 1");
    };

    if ($@) {
        $log->debug("Database connection test failed: $@");
        return 0;
    }

    return 1;
}

=head2 upsert_blocked_ip_batch

    my $count = $pg->upsert_blocked_ip_batch($dbh, \@rows);

Inserts or updates a batch of blocked IP records using PostgreSQL's
ON CONFLICT clause for efficient upserts.

Arguments:
    $dbh  => DBI database handle
    $rows => Arrayref of hashrefs with keys:
        ip                  => IP address
        originating_server  => Server hostname
        originating_service => Service name (optional)
        detector_name       => Detector name (optional)
        pattern_matched     => Pattern that matched (optional)
        matched_log_line    => Log line that triggered block (optional)
        first_blocked_at    => Unix timestamp
        last_seen_at        => Unix timestamp
        expires_at          => Unix timestamp
        block_count         => Number of times blocked (default: 1)

Returns:
    Number of rows upserted.

=cut

sub upsert_blocked_ip_batch {
    my ($self, $dbh, $rows) = @_;

    return 0 unless $rows && @$rows;

    my $hostname = hostname();
    chomp $hostname;

    # Build multi-row INSERT statement
    my $sql = "INSERT INTO jailed_ips (
        ip, originating_server, originating_service, detector_name,
        pattern_matched, matched_log_line,
        first_blocked_at, last_seen_at, expires_at, block_count
    ) VALUES ";

    my @placeholders;
    my @values;

    for my $row (@$rows) {
        push @placeholders, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        push @values,
            $row->{ip},
            $row->{originating_server} || $hostname,
            $row->{originating_service} || 'unknown',
            $row->{detector_name}       || 'unknown',
            $row->{pattern_matched}     || 'unknown',
            substr($row->{matched_log_line} || '', 0, 500),
            $row->{first_blocked_at},
            $row->{last_seen_at},
            $row->{expires_at},
            $row->{block_count} || 1;
    }

    $sql .= join(", ", @placeholders);
    $sql .= " ON CONFLICT(ip, originating_server) DO UPDATE SET
        last_seen_at     = EXCLUDED.last_seen_at,
        expires_at       = EXCLUDED.expires_at,
        block_count      = jailed_ips.block_count + 1,
        pattern_matched  = EXCLUDED.pattern_matched,
        matched_log_line = EXCLUDED.matched_log_line";

    my $sth = $dbh->prepare($sql);
    $sth->execute(@values);

    my $count = scalar @$rows;
    $log->debug("Upserted $count blocked IP entries");
    return $count;
}

=head2 pull_global_blocks

    my $blocks = $pg->pull_global_blocks($dbh, $hostname, $last_check);

Pulls blocked IPs from the central database that were blocked by other
servers since the last check.

Arguments:
    $dbh        => DBI database handle
    $hostname   => This server's hostname
    $last_check => Unix timestamp of last check

Returns:
    Arrayref of hashrefs with keys:
        ip         => IP address
        expires_at => Unix timestamp when block expires

=cut

sub pull_global_blocks {
    my ($self, $dbh, $hostname, $last_check) = @_;

    # Query for IPs blocked by other servers that are still active
    my $sql = q{
        SELECT DISTINCT ip, expires_at, last_seen_at
        FROM jailed_ips
        WHERE originating_server != ?
          AND last_seen_at > ?
          AND expires_at > EXTRACT(EPOCH FROM NOW())
        ORDER BY last_seen_at DESC
    };

    my $sth = $dbh->prepare($sql);
    $sth->execute($hostname, int($last_check));

    my @blocks;
    while (my $row = $sth->fetchrow_hashref()) {
        push @blocks, {
            ip         => $row->{ip},
            expires_at => $row->{expires_at},
        };
    }

    $log->debug("Pulled " . scalar(@blocks) . " global blocks from central DB");
    return \@blocks;
}

1;

__END__

=head1 AUTHOR

Bad IPs Project

=head1 LICENSE

Copyright (c) 2025 Silver Linings, LLC. All rights reserved.

=cut
