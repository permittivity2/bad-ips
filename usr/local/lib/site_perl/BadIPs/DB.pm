package BadIPs::DB;

use strict;
use warnings;
use Log::Log4perl qw(get_logger);

our $VERSION = '3.4.7';

my $log = get_logger("BadIPs::DB");

=head1 NAME

BadIPs::DB - Database abstraction layer for Bad IPs

=head1 SYNOPSIS

    use BadIPs::DB;

    my $db = BadIPs::DB->new(
        db_type     => 'postgres',
        db_host     => 'localhost',
        db_port     => 5432,
        db_name     => 'bad_ips',
        db_user     => 'bad_ips',
        db_password => 'password',
        db_ssl_mode => 'prefer',
    );

    # Connect to database
    my $dbh = $db->connect();

    # Upsert blocked IPs
    $db->upsert_blocked_ip_batch($dbh, \@rows);

    # Pull global blocks
    my @blocks = $db->pull_global_blocks($dbh, $hostname, $last_check);

    # Disconnect
    $db->disconnect($dbh);

=head1 DESCRIPTION

BadIPs::DB provides a database abstraction layer for the Bad IPs system.
It supports multiple database backends through a plugin architecture.

Currently supported backends:
- PostgreSQL (via BadIPs::DB::Postgres)

Future backends:
- MySQL (via BadIPs::DB::MySQL)
- SQLite (via BadIPs::DB::SQLite)

=head1 METHODS

=head2 new

    my $db = BadIPs::DB->new(%options);

Creates a new BadIPs::DB object and loads the appropriate backend.

Options:
    db_type     => Database type (required): 'postgres', 'mysql', 'sqlite'
    db_host     => Database hostname
    db_port     => Database port
    db_name     => Database name
    db_user     => Database username
    db_password => Database password
    db_ssl_mode => SSL mode (postgres only)

=cut

sub new {
    my ($class, %args) = @_;

    die "db_type is required" unless $args{db_type};

    my $db_type = lc $args{db_type};

    my %supported = (
        postgres => "BadIPs::DB::Postgres",
        # mysql    => "BadIPs::DB::MySQL",
        # sqlite   => "BadIPs::DB::SQLite",
    );

    my $backend_class = $supported{$db_type}
        or die "Unsupported db_type '$db_type'. Supported: " . join(", ", keys %supported);

    # Load the backend module dynamically
    eval "require $backend_class;";
    die "Failed loading backend $backend_class: $@" if $@;

    # Create backend instance
    my $backend = $backend_class->new(%args);

    my $self = {
        db_type => $db_type,
        backend => $backend,
    };

    bless $self, $class;
    $log->debug("Initialized BadIPs::DB with backend: $backend_class");
    return $self;
}

=head2 connect

    my $dbh = $db->connect();

Establishes a database connection and returns a DBI handle.

Returns:
    DBI database handle on success, undef on failure.

=cut

sub connect {
    my ($self) = @_;
    return $self->{backend}->connect();
}

=head2 disconnect

    $db->disconnect($dbh);

Closes a database connection.

Arguments:
    $dbh => DBI database handle

Returns:
    Nothing.

=cut

sub disconnect {
    my ($self, $dbh) = @_;
    return unless $dbh;

    eval {
        $dbh->disconnect();
    };
    if ($@) {
        $log->warn("Error disconnecting from database: $@");
    }
}

=head2 test_connection

    my $ok = $db->test_connection($dbh);

Tests if a database connection is alive.

Arguments:
    $dbh => DBI database handle

Returns:
    1 if connection is alive, 0 otherwise.

=cut

sub test_connection {
    my ($self, $dbh) = @_;
    return $self->{backend}->test_connection($dbh);
}

=head2 upsert_blocked_ip_batch

    my $count = $db->upsert_blocked_ip_batch($dbh, \@rows);

Inserts or updates a batch of blocked IP records.

Arguments:
    $dbh  => DBI database handle
    $rows => Arrayref of hashrefs with keys:
        ip                  => IP address
        originating_server  => Server hostname
        originating_service => Service name
        detector_name       => Detector name
        pattern_matched     => Pattern that matched
        matched_log_line    => Log line that triggered block
        first_blocked_at    => Unix timestamp
        last_seen_at        => Unix timestamp
        expires_at          => Unix timestamp
        block_count         => Number of times blocked

Returns:
    Number of rows upserted.

=cut

sub upsert_blocked_ip_batch {
    my ($self, $dbh, $rows) = @_;
    return $self->{backend}->upsert_blocked_ip_batch($dbh, $rows);
}

=head2 pull_global_blocks

    my @blocks = $db->pull_global_blocks($dbh, $hostname, $last_check);

Pulls blocked IPs from the central database that were blocked by other servers.

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
    return $self->{backend}->pull_global_blocks($dbh, $hostname, $last_check);
}

1;

__END__

=head1 AUTHOR

Bad IPs Project

=head1 LICENSE

Copyright (c) 2025 Silver Linings, LLC. All rights reserved.

=cut
