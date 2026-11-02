package TestPg;

# A private, throwaway PostgreSQL for tests: started in a temp directory
# (unix socket only, no TCP) with the fleet's role layout -- schema `badips`
# owned by badips_migrate, the daemon connecting as badips_runtime through
# default privileges -- and the shipped schema.sql applied as the owner.
#
#   my $pg = TestPg->start or plan skip_all => 'no PostgreSQL';
#   my $db = $pg->db;      # settings for BadIPs::Engine::Store
#   $pg->su;               # a superuser handle

use strict;
use warnings;
use File::Temp qw(tempdir);
use FindBin;
use DBI;

# Never inherit the caller's libpq settings (this workstation sets PGHOST to
# a real server); everything here names its socket and port explicitly.
delete @ENV{qw(PGHOST PGHOSTADDR PGPORT PGUSER PGDATABASE PGPASSWORD PGSERVICE PGSSLMODE)};

my @started;
END { system("$_->{bin}/pg_ctl -D $_->{dir}/data -m immediate stop >/dev/null 2>&1") for @started }

sub start {
    my ($class, %a) = @_;
    my ($bin) = sort { $b cmp $a } glob('/usr/lib/postgresql/*/bin');
    return undef unless $bin && -x "$bin/initdb";
    my $port = $a{port} // 54329 + int(rand(500));
    my $dir  = tempdir(CLEANUP => 1);
    system("$bin/initdb -D $dir/data -A trust -U postgres --no-sync >$dir/initdb.log 2>&1") == 0 or return undef;
    system("$bin/pg_ctl -D $dir/data -l $dir/server.log -w -o \"-k $dir -p $port -c listen_addresses='' -c fsync=off\" start >/dev/null 2>&1") == 0
        or return undef;
    my $self = bless { bin => $bin, dir => $dir, port => $port }, $class;
    push @started, $self;

    my $su = $self->su;
    local $su->{PrintWarn} = 0;
    $su->do($_) for (
        'SET client_min_messages = warning',
        'CREATE ROLE badips_migrate LOGIN', 'CREATE ROLE badips_runtime LOGIN',
        'CREATE SCHEMA badips AUTHORIZATION badips_migrate',
        'GRANT USAGE ON SCHEMA badips TO badips_runtime',
        'ALTER DEFAULT PRIVILEGES FOR ROLE badips_migrate IN SCHEMA badips GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO badips_runtime',
        'ALTER DEFAULT PRIVILEGES FOR ROLE badips_migrate IN SCHEMA badips GRANT USAGE, SELECT ON SEQUENCES TO badips_runtime',
    );
    $self->apply_schema;
    return $self;
}

sub apply_schema {
    my ($self) = @_;
    my $schema = do { open my $fh, '<', "$FindBin::Bin/../usr/local/share/bad_ips/schema.sql" or die; local $/; <$fh> };
    my $su = $self->su;
    $su->do('SET client_min_messages = warning');
    $su->do('SET ROLE badips_migrate');
    $su->do('SET search_path = badips');
    $su->do($schema);
    $su->do('RESET ROLE');
}

sub su {
    my ($self) = @_;
    $self->{su} ||= DBI->connect("dbi:Pg:dbname=postgres;host=$self->{dir};port=$self->{port}", 'postgres', '',
                                 { RaiseError => 1, PrintError => 0 });
    return $self->{su};
}

sub db {
    my ($self) = @_;
    return { host => $self->{dir}, port => $self->{port}, name => 'postgres', user => 'badips_runtime',
             password => '', sslmode => 'disable', schema => 'badips' };
}

# The same settings as config-file lines.
sub db_conf {
    my ($self) = @_;
    my $d = $self->db;
    return join '', map { "$_->[0] = $_->[1]\n" }
        [ db_host => $d->{host} ], [ db_port => $d->{port} ], [ db_name => $d->{name} ], [ db_user => $d->{user} ],
        [ db_password => 'unused' ], [ db_ssl_mode => 'disable' ], [ db_schema => 'badips' ];
}

1;
