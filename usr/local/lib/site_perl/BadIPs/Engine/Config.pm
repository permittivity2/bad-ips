package BadIPs::Engine::Config;

# ============================================================================
# Configuration for role mode (bad-ips 4.0).
#
# Reads the same INI files as the legacy daemon -- badips.conf, then
# badips.d/*.conf in sorted order -- with these rules:
#
#   * [global] keys: a later file replaces an earlier file's value -- EXCEPT
#     the settings that decide what happens to traffic and where detections
#     go (role, dry_run, block_interfaces, the never-block lists, and the
#     database settings as a group). Each of those may come from ONE file:
#     two files that disagree are refused, naming both. "A later file wins"
#     would pick one by its file NAME, and the loser is usually a leftover.
#     Found 2026-11-02: a purged 3.x install had left badips.d/database.conf
#     (a dead database) on every node of a fleet, and "database.conf" sorts
#     after "96-fleet-db.conf", so it silently won.
#   * [host:<short hostname>] keys: applied after ALL [global] sections, so
#     a host section always wins regardless of which file it is in (that is
#     a deliberate per-host override, not a conflict).
#   * [rule:NAME] and [feed:NAME]: merged BY NAME. A later file's section
#     replaces the earlier one whole, and "active = 0" there switches it
#     off. (3.x merged detector sections per file, so a later file could
#     never switch off a shipped rule.)
#   * Legacy sections ([detector:*], [Plugins:*], [PublicBlocklistPlugins:*])
#     are ignored in role mode and listed by --test-config.
#
# Any error makes load() return errors and the daemon refuse to start: a
# config that is half-understood is never run.
# ============================================================================

use strict;
use warnings;

use Config::Tiny;
use Sys::Hostname ();
use BadIPs::Engine::Net;
use BadIPs::Engine::Rules;

my %ROLES = map { $_ => 1 } qw(block report off);

# One file each (see the header). The database settings are one group: host,
# port, name, user and password from different files are never mixed.
my @SINGLE = qw(role dry_run block_interfaces never_block_cidrs never_block_cidrs_v6);
my @DBKEYS = qw(db_host db_port db_name db_user db_password db_schema db_ssl_mode);

=head2 role_from_files(conf_main => ..., conf_dir => ...)

Just the role (or undef when no file sets one), cheaply, so bin/bad_ips can
decide between legacy mode and role mode before loading anything else.

=cut

sub role_from_files {
    my (%a) = @_;
    my $raw = _read_all(%a);
    my $g   = _merge_scalars($raw, _short_host($a{host}));
    return $g->{role};
}

sub _short_host {
    my ($h) = @_;
    $h //= Sys::Hostname::hostname();
    $h =~ s/\..*//;
    return $h;
}

sub _files {
    my (%a) = @_;
    my @f;
    push @f, $a{conf_main} if $a{conf_main} && -f $a{conf_main};
    if ($a{conf_dir} && -d $a{conf_dir}) {
        opendir(my $dh, $a{conf_dir}) or return @f;
        push @f, map { "$a{conf_dir}/$_" } sort grep { /\.conf\z/ && -f "$a{conf_dir}/$_" } readdir $dh;
        closedir $dh;
    }
    return @f;
}

sub _read_all {
    my (%a) = @_;
    my @out;
    for my $f (_files(%a)) {
        my $c = Config::Tiny->read($f);
        push @out, { file => $f, conf => $c, error => ($c ? undef : Config::Tiny->errstr) };
    }
    return \@out;
}

sub _merge_scalars {
    my ($raw, $host) = @_;
    my %g;
    for my $r (@$raw) { next unless $r->{conf}; %g = (%g, %{ $r->{conf}{global} || {} }) }
    for my $r (@$raw) { next unless $r->{conf}; %g = (%g, %{ $r->{conf}{"host:$host"} || {} }) }
    return \%g;
}

# Where each key of one layer ([global], or [host:<me>]) is set:
# key => [ [file, value], ... ] in file order.
sub _settings_by_file {
    my ($raw, $section) = @_;
    my %by;
    for my $r (@$raw) {
        next unless $r->{conf} && $r->{conf}{$section};
        push @{ $by{$_} }, [ $r->{file}, $r->{conf}{$section}{$_} ] for sort keys %{ $r->{conf}{$section} };
    }
    return \%by;
}

sub _same { my ($v) = @_; $v //= ''; $v =~ s/\s*,\s*/,/g; $v =~ s/\A\s+|\s+\z//g; return $v }

# The one-file-each rule, for one layer. Returns the errors.
sub _conflicts {
    my ($by, $where) = @_;
    my @err;
    for my $k (@SINGLE) {
        my @set = @{ $by->{$k} || [] };
        my %distinct = map { _same($_->[1]) => 1 } @set;
        next unless keys %distinct > 1;
        push @err, "$k is set differently by more than one file in $where: "
            . join('; ', map { "$_->[0] says '$_->[1]'" } @set) . ' -- keep it in exactly one file';
    }
    my %dbfile;
    for my $k (@DBKEYS) { $dbfile{ $_->[0] }{$k} = $_->[1] for @{ $by->{$k} || [] } }
    if (keys %dbfile > 1) {
        my $show = sub {
            my ($f) = @_;
            return "$f (" . join(', ', map { $_ eq 'db_password' ? 'db_password' : "$_=$dbfile{$f}{$_}" }
                                       grep { exists $dbfile{$f}{$_} } @DBKEYS) . ')';
        };
        push @err, "the database settings in $where come from more than one file: "
            . join('; ', map { $show->($_) } sort keys %dbfile)
            . ' -- they must all come from one file (a leftover badips.d/database.conf from an older install is the usual cause)';
    }
    return @err;
}

=head2 load(conf_main => ..., conf_dir => ..., host => ...)

Returns ($settings, \@errors, \@notes).

=cut

sub load {
    my (%a) = @_;
    my @err;
    my @notes;
    my $host = _short_host($a{host});
    my $raw  = _read_all(%a);

    for my $r (@$raw) {
        push @err, "$r->{file}: cannot be parsed: $r->{error}" unless $r->{conf};
    }

    my $g = _merge_scalars($raw, $host);

    # one file each for what matters; and where every setting came from
    my $gby = _settings_by_file($raw, 'global');
    my $hby = _settings_by_file($raw, "host:$host");
    push @err, _conflicts($gby, '[global]'), _conflicts($hby, "[host:$host]");
    my %from = ((map { $_ => $gby->{$_}[-1][0] } keys %$gby), (map { $_ => $hby->{$_}[-1][0] } keys %$hby));

    my (%rules, %feeds, %ignored);
    for my $r (@$raw) {
        next unless $r->{conf};
        for my $s (sort keys %{ $r->{conf} }) {
            my $sec = $r->{conf}{$s};
            if    ($s =~ /\Arule:([A-Za-z0-9_.-]+)\z/) { $rules{$1} = { %$sec, _file => $r->{file} } }
            elsif ($s =~ /\Afeed:([A-Za-z0-9_.-]+)\z/) { $feeds{$1} = { %$sec, _file => $r->{file} } }
            elsif ($s =~ /\A(?:detector|Plugins|PublicBlocklistPlugins):/) { $ignored{$s}++ }
            elsif ($s =~ /\A(?:global|host:.*|_)\z/) { }
            else { push @err, "$r->{file}: unknown section [$s]" }
        }
    }
    push @notes, "legacy sections ignored in role mode: " . join(', ', sort keys %ignored) if %ignored;

    my %s = (host => $g->{host_name} // $host, from => \%from);

    # role
    my $role = $g->{role} // '';
    push @err, "role must be one of: block, report, off (got '$role')" unless $ROLES{$role};
    $s{role} = $role;

    # booleans and numbers
    for my $k ([dry_run => 0], [dns_accept => 1]) {
        my ($n, $def) = @$k;
        my $v = $g->{$n} // $def;
        if ($v =~ /\A[01]\z/) { $s{$n} = $v + 0 } else { push @err, "$n must be 0 or 1" }
    }
    for my $k ([sleep_time => 2, 1, 60], [push_interval => 5, 1, 300], [reconcile_interval => 30, 5, 600],
               [exemption_refresh => 60, 10, 3600], [heartbeat => 300, 30, 86400], [metrics_interval => 30, 5, 3600],
               [exemption_hours => 24, 1, 24 * 90], [backread_bytes => 2 * 1024 * 1024, 0, 512 * 1024 * 1024],
               [max_read_bytes => 8 * 1024 * 1024, 65536, 1024 * 1024 * 1024], [queue_max => 5000, 100, 1_000_000]) {
        my ($n, $def, $min, $max) = @$k;
        my $v = $g->{$n} // $def;
        if ($v !~ /\A\d+\z/ || $v < $min || $v > $max) { push @err, "$n must be a whole number from $min to $max" }
        else { $s{$n} = $v + 0 }
    }
    $s{state_dir} = $g->{state_dir} // '/var/lib/bad_ips';
    $s{cache_dir} = $g->{cache_dir} // '/var/cache/badips';
    # where the metrics file goes (node_exporter's textfile directory); empty = publish nothing
    $s{geo_dir} = $g->{geo_dir} // '/var/lib/bad_ips/geo';    # DB-IP data for country/owner (block role)
    $s{metrics_dir} = $g->{metrics_dir} // '/var/lib/prometheus/node-exporter';

    # never-block: v4 and v6 lists are one list here
    my @nb = map { split /\s*,\s*/ } grep { defined } $g->{never_block_cidrs}, $g->{never_block_cidrs_v6};
    my $never = BadIPs::Engine::NeverBlock->new(@nb);
    push @err, $never->errors;
    $s{never} = $never;

    # interfaces the block role drops on (empty = every interface)
    my @if = grep { length } split /\s*,\s*/, ($g->{block_interfaces} // '');
    for (@if) { push @err, "block_interfaces: '$_' is not an interface name" unless /\A[A-Za-z0-9_.-]{1,15}\z/ }
    push @err, "block_interfaces: at most 16 interfaces" if @if > 16;
    $s{block_interfaces} = \@if;

    # database (all of host/name/user/password, or none)
    my @dbk = qw(db_host db_name db_user db_password);
    my @have = grep { defined $g->{$_} && length $g->{$_} } @dbk;
    if (@have && @have < @dbk) {
        my %h = map { $_ => 1 } @have;
        push @err, "database settings incomplete: missing " . join(', ', grep { !$h{$_} } @dbk);
    }
    if (@have == @dbk) {
        $s{db} = {
            host     => $g->{db_host},
            port     => $g->{db_port} // 5432,
            name     => $g->{db_name},
            user     => $g->{db_user},
            password => $g->{db_password},
            sslmode  => $g->{db_ssl_mode} // 'prefer',
            schema   => $g->{db_schema},
            from     => $from{db_host},
        };
        push @err, "db_port must be a port number" unless $s{db}{port} =~ /\A\d{1,5}\z/;
        push @err, "db_schema must be a plain identifier"
            if defined $s{db}{schema} && $s{db}{schema} !~ /\A[a-z_][a-z0-9_]{0,62}\z/;
        push @err, "db_ssl_mode must be one of disable, allow, prefer, require, verify-ca, verify-full"
            unless $s{db}{sslmode} =~ /\A(?:disable|allow|prefer|require|verify-ca|verify-full)\z/;
    }
    push @err, "role = report needs the database settings (it has nowhere else to report to)"
        if $role eq 'report' && !$s{db};

    # rules
    my @rules;
    for my $name (sort keys %rules) {
        my $sec = $rules{$name};
        my $active = $sec->{active} // 1;
        push @err, "rule $name: active must be 0 or 1" unless $active =~ /\A[01]\z/;
        next unless $active;
        my ($r, $e) = BadIPs::Engine::Rules::compile_rule($name, $sec);
        push @err, map { "rule $name ($sec->{_file}): $_" } @$e;
        push @rules, $r if $r;
    }
    $s{rules} = \@rules;
    push @notes, "no rules are active" if !@rules && $role ne 'off';

    # feeds (only the block role ever loads them)
    my @feeds;
    for my $name (sort keys %feeds) {
        my $f = $feeds{$name};
        my $active = $f->{active} // 1;
        push @err, "feed $name: active must be 0 or 1" unless $active =~ /\A[01]\z/;
        next unless $active;
        my @urls = grep { length } split /\s*,\s*/, ($f->{urls} // '');
        push @err, "feed $name: urls is required" unless @urls;
        for (@urls) { push @err, "feed $name: '$_' is not an http(s) URL" unless m{\Ahttps?://\S+\z} }
        my $interval = $f->{interval} // 86400;
        push @err, "feed $name: interval must be at least 3600" unless $interval =~ /\A\d+\z/ && $interval >= 3600;
        my $min = $f->{min_entries} // 10;
        push @err, "feed $name: min_entries must be a whole number" unless $min =~ /\A\d+\z/;
        push @feeds, { name => $name, urls => \@urls, interval => $interval + 0, min_entries => $min + 0 };
    }
    $s{feeds} = \@feeds;

    return (\%s, \@err, \@notes);
}

1;
