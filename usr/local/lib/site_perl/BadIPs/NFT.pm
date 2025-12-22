package BadIPs::NFT;

use strict;
use warnings;
use JSON;
use Log::Log4perl qw(get_logger);

our $VERSION = '3.5.0';

my $log = get_logger("BadIPs::NFT");

# Acceptable nft error messages and their log levels
# These errors are non-fatal and should be logged at the specified level
my %nft_acceptable_errors = (
    "interval overlaps with an existing one" => "info",  # IP/CIDR already in set
    "Could not process rule: No such file or directory" => "warn",  # Set doesn't exist (shouldn't happen but not fatal)
);

=head1 NAME

BadIPs::NFT - nftables integration for Bad IPs 

=head1 SYNOPSIS

    use BadIPs::NFT;

    my $nft = BadIPs::NFT->new(
        table        => 'inet',
        family_table => 'badips',
        dry_run      => 0,
    );

    # Block an IP
    my $result = $nft->block_ip(
        ip  => '1.2.3.4',
        ttl => 691200,
    );

    # Refresh static sets
    $nft->refresh_static_sets(
        never_block_cidrs     => ['10.0.0.0/8', '192.168.0.0/16'],
        never_block_cidrs_v6  => ['::1/128', 'fe80::/10'],
        always_block_cidrs    => ['224.0.0.0/4'],
        always_block_cidrs_v6 => [],
    );

    # Get nftables ruleset as JSON
    my $ruleset = $nft->ruleset_as_json();

=head1 DESCRIPTION

BadIPs::NFT provides a clean interface for managing nftables sets and rules
for the Bad IPs system. It handles both IPv4 and IPv6 addresses, supports
dry-run mode, and provides detailed error reporting.

=head1 METHODS

=head2 new

    my $nft = BadIPs::NFT->new(%options);

Creates a new BadIPs::NFT object.

Options:
    table        => 'inet'     # nftables table (default: inet)
    family_table => 'badips'   # table family name (default: badips)
    dry_run      => 0          # if true, don't execute commands (default: 0)

=cut

sub new {
    my ($class, %args) = @_;

    my $self = {
        table        => $args{table}        || 'inet',
        family_table => $args{family_table} || 'badips',
        dry_run      => $args{dry_run}      || 0,
    };

    return bless $self, $class;
}

=head2 block_ip

    my $result = $nft->block_ip(
        ip  => '1.2.3.4',
        ttl => 691200,
    );

Blocks a single IP address by adding it to the appropriate nftables set
(badipv4 or badipv6) with a timeout.

Arguments:
    ip  => IP address (IPv4 or IPv6)
    ttl => Time to live in seconds

Returns:
    Hashref with:
        ok      => 1 on success, 0 on failure
        expires => epoch time when block expires (on success)
        out     => command output (on success)
        err     => error message (on failure)
        rc      => return code (on failure)

=cut

sub block_ip {
    my ($self, %args) = @_;
    my $ip  = $args{ip};
    my $ttl = $args{ttl};

    unless (defined $ip && defined $ttl) {
        return { ok => 0, err => "ip and ttl are required" };
    }

    # Detect IPv6 (contains colons) vs IPv4 and use appropriate set
    my $set = ($ip =~ /:/) ? 'badipv6' : 'badipv4';

    my $cmd = "sudo nft add element $self->{table} $self->{family_table} $set { $ip timeout ${ttl}s }";

    if ($self->{dry_run}) {
        my $exp = time() + $ttl;
        $log->info("[DRY RUN] Would execute: $cmd");
        return { ok => 1, expires => $exp, dry_run => 1 };
    }

    my ($out, $rc);
    eval {
        $out = qx($cmd 2>&1);
        $rc  = $? >> 8;
    };
    if ($@) {
        my $err = "Command execution failed: $@";
        $log->error("$err (command: $cmd, output: $out)");
        return { ok => 0, err => $err, rc => -1 };
    }

    if ($rc == 0) {
        my $exp = time() + $ttl;
        $log->debug("Blocked $ip in $set set (expires: $exp)");
        return { ok => 1, expires => $exp, out => $out };
    }

    # Check if this is an acceptable error (non-fatal)
    my ($ok, $level, $pattern) = _check_nft_error($out, $rc);

    if ($ok) {
        # Acceptable error - log at appropriate level and treat as success
        my $exp = time() + $ttl;
        if ($level eq 'info') {
            $log->info("Blocked $ip (acceptable condition: $pattern)");
        } elsif ($level eq 'debug') {
            $log->debug("Blocked $ip (acceptable condition: $pattern)");
        } elsif ($level eq 'warn') {
            $log->warn("Blocked $ip (acceptable condition: $pattern)");
        }
        return { ok => 1, expires => $exp, out => $out, acceptable_error => $pattern };
    }

    # Real error - log and return failure
    $log->warn("Failed to block $ip: $out (rc: $rc)");
    return { ok => 0, err => $out, rc => $rc };
}

=head2 refresh_static_sets

    $nft->refresh_static_sets(
        never_block_cidrs     => \@ipv4_cidrs,
        never_block_cidrs_v6  => \@ipv6_cidrs,
        always_block_cidrs    => \@ipv4_cidrs,
        always_block_cidrs_v6 => \@ipv6_cidrs,
    );

Refreshes the static nftables sets (never_block, always_block) by flushing
and repopulating them with the provided CIDRs.

Arguments:
    never_block_cidrs     => arrayref of IPv4 CIDRs to never block
    never_block_cidrs_v6  => arrayref of IPv6 CIDRs to never block
    always_block_cidrs    => arrayref of IPv4 CIDRs to always block
    always_block_cidrs_v6 => arrayref of IPv6 CIDRs to always block

Returns:
    Nothing. Logs errors if any CIDRs fail to add.

=cut

sub refresh_static_sets {
    my ($self, %args) = @_;

    my $never_cidrs     = $args{never_block_cidrs}     || [];
    my $never_cidrs_v6  = $args{never_block_cidrs_v6}  || [];
    my $always_cidrs    = $args{always_block_cidrs}    || [];
    my $always_cidrs_v6 = $args{always_block_cidrs_v6} || [];

    # IPv4 never_block
    $self->_refresh_set('never_block', $never_cidrs, 'IPv4');

    # IPv6 never_block
    $self->_refresh_set('never_block_v6', $never_cidrs_v6, 'IPv6');

    # IPv4 always_block
    $self->_refresh_set('always_block', $always_cidrs, 'IPv4');

    # IPv6 always_block
    $self->_refresh_set('always_block_v6', $always_cidrs_v6, 'IPv6');

    $log->info("Static sets refreshed: "
        . scalar(@$never_cidrs) . " never_block (IPv4), "
        . scalar(@$never_cidrs_v6) . " never_block_v6 (IPv6), "
        . scalar(@$always_cidrs) . " always_block (IPv4), "
        . scalar(@$always_cidrs_v6) . " always_block_v6 (IPv6)");
}

=head2 ruleset_as_json

    my $ruleset = $nft->ruleset_as_json();

Returns the current nftables ruleset as a parsed JSON structure.

Returns:
    Hashref representing the nftables ruleset in JSON format.

=cut

sub ruleset_as_json {
    my ($self) = @_;

    my $out = `sudo nft -j list ruleset`;
    unless ($out) {
        $log->error("Failed to get nftables ruleset");
        return {};
    }

    my $json;
    eval {
        $json = decode_json($out);
    };
    if ($@) {
        $log->error("Failed to parse nftables JSON: $@");
        return {};
    }

    return $json;
}

=head2 _check_nft_error (private)

Internal helper to check if an nft error is acceptable (non-fatal).

Arguments:
    $out => Command output/error message
    $rc  => Return code

Returns:
    ($ok, $level, $pattern) where:
        $ok      => 1 if acceptable error, 0 if real error
        $level   => Log level to use ('info', 'debug', 'warn', 'error')
        $pattern => Matched error pattern (undef if real error)

=cut

sub _check_nft_error {
    my ($out, $rc) = @_;

    # Return code 0 = success, always OK
    return (1, 'debug', 'success') if $rc == 0;

    # Check if error message contains any acceptable patterns
    for my $pattern (keys %nft_acceptable_errors) {
        if ($out =~ /\Q$pattern\E/i) {
            my $level = $nft_acceptable_errors{$pattern};
            return (1, $level, $pattern);
        }
    }

    # Unrecognized error
    return (0, 'error', undef);
}

=head2 _refresh_set (private)

Internal helper to refresh a single nftables set.

=cut

sub _refresh_set {
    my ($self, $set_name, $cidrs, $version) = @_;

    $log->info("Refreshing $set_name ($version) nftables set");

    my $table        = $self->{table};
    my $family_table = $self->{family_table};

    # Flush the set
    if ($self->{dry_run}) {
        $log->info("[DRY RUN] Would flush: sudo nft flush set $table $family_table $set_name");
    } else {
        system("sudo nft flush set $table $family_table $set_name 2>/dev/null");
    }

    # Add each CIDR
    for my $cidr (@$cidrs) {
        next unless $cidr;
        $cidr =~ s/^\s+|\s+$//g;
        next unless $cidr;

        my $cmd = "sudo nft add element $table $family_table $set_name { $cidr }";

        if ($self->{dry_run}) {
            $log->info("[DRY RUN] Would execute: $cmd");
            next;
        }

        my $out = qx($cmd 2>&1);
        my $rc = $? >> 8;

        if ($rc == 0) {
            $log->debug("Added $cidr to $set_name set");
        } else {
            # Check if this is an acceptable error
            my ($ok, $level, $pattern) = _check_nft_error($out, $rc);

            if ($ok) {
                # Acceptable error - log at appropriate level
                if ($level eq 'info') {
                    $log->info("Added $cidr to $set_name set (acceptable condition: $pattern)");
                } elsif ($level eq 'debug') {
                    $log->debug("Added $cidr to $set_name set (acceptable condition: $pattern)");
                } elsif ($level eq 'warn') {
                    $log->warn("Added $cidr to $set_name set (acceptable condition: $pattern)");
                }
            } else {
                # Real error
                $log->warn("Failed to add $cidr to $set_name set: $out (rc: $rc)");
            }
        }
    }
}

1;

__END__

=head1 AUTHOR

Bad IPs Project

=head1 LICENSE

Copyright (c) 2025 Silver Linings, LLC. All rights reserved.

=cut
