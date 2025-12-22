package BadIPs::PublicBlocklistPlugins::Spamhaus;

use strict;
use warnings;
use LWP::UserAgent;
use Log::Log4perl qw(get_logger);
use Regexp::Common qw(net);  # Exports %RE{net}
use File::Path qw(make_path);
use Digest::MD5 qw(md5_hex);
use Data::Dumper;
our $VERSION = '3.5.0';
my $log = get_logger("BadIPs::PublicBlocklistPlugins::Spamhaus");

=head1 NAME

BadIPs::PublicBlocklistPlugins::Spamhaus - Plugin to fetch and process Spamhaus blocklists

=cut

sub new {
    my ($class, %args) = @_;

    my $self = {
        conf           => $args{conf},
        dry_run        => $args{dry_run} || 0,
        log            => $args{log} || get_logger(__PACKAGE__),
        reload_check   => $args{reload_check},
        shutdown_check => $args{shutdown_check},
        enqueue_ip     => $args{enqueue_ip},
    };

    # Optional sanity checks
    # ref($self->{reload_check})   eq 'CODE' or die "Expected reload_check to be a coderef";
    # ref($self->{shutdown_check}) eq 'CODE' or die "Expected shutdown_check to be a coderef";
    # ref($self->{enqueue_ip})     eq 'CODE' or die "Expected enqueue_ip to be a coderef";

    bless $self, $class;
    return $self;
}

sub reload_check {
    my ($self) = @_;
    my $cb = $self->{reload_check} or return 0;
    return $cb->();
}

sub shutdown_check {
    my ($self) = @_;
    my $cb = $self->{shutdown_check} or return 0;
    return $cb->();
}

sub enqueue_ip {
    my ($self, %args) = @_;
    my $cb = $self->{enqueue_ip} or return;
    return $cb->(%args);
}

sub run {
    my ($self) = @_;

    my $conf = $self->{conf} || {};
    Log::Log4perl::MDC->put("THREAD" => $conf->{thread_name} || (split /::/, __PACKAGE__)[-1]);

    my $log = $self->{log};

    my $urls = $conf->{PublicBlocklistPlugins}->{Spamhaus}->{urls} || [];
    $urls = [ $urls ] if ref($urls) ne 'ARRAY';

    my $interval   = $conf->{PublicBlocklistPlugins}->{Spamhaus}->{fetch_interval} || 3600;
    my $use_cache  = defined $conf->{PublicBlocklistPlugins}->{Spamhaus}->{use_cache}
                     ? $conf->{PublicBlocklistPlugins}->{Spamhaus}->{use_cache}
                     : 1;
    my $cache_path = $conf->{PublicBlocklistPlugins}->{Spamhaus}->{cache_path}
                     || '/var/cache/badips/spamhaus';

    my $active_defined = defined $conf->{PublicBlocklistPlugins}->{Spamhaus}->{active};
    my $active = $active_defined
                 ? $conf->{PublicBlocklistPlugins}->{Spamhaus}->{active}
                 : 1;

    if ($active_defined && !$active) {
        $log->info("Spamhaus blocklist plugin is disabled in configuration; exiting");
        return 1;
    }

    if (!@$urls) {
        $log->warn("No URLs configured for Spamhaus blocklist; using default URL");
        @$urls = ('https://www.spamhaus.org/drop/drop.txt');
    }

    $log->info("Starting Spamhaus blocklist plugin");

    if ($use_cache && ! -d $cache_path) {
        eval { make_path($cache_path) };
        if ($@) {
            $log->warn("public_blocklist_thread: failed to create cache dir $cache_path: $@; disabling cache");
            $use_cache = 0;
        }
    }

    my $ua = LWP::UserAgent->new(
        timeout  => 10,
        agent    => "BadIPs/3.0",
        ssl_opts => { verify_hostname => 1 },
        max_size => 5_000_000,
    );

    while (1) {
        if ( $self->shutdown_check() ) {
            $log->info("Spamhaus blocklist plugin shutting down as requested");
            last;
        }
        if ( $self->reload_check() ) {
            $log->info("Spamhaus blocklist exitting for reload as requested");
            last;
        }

        URL:
        for my $url (@$urls) {
            next URL unless $url;
            $log->info("public_blocklist_thread: processing source $url");

            my $url_md5    = md5_hex($url);
            my $cache_file = "$cache_path/blocklist_$url_md5.txt";
            my $etag_file  = "$cache_path/blocklist_$url_md5.etag";
            my $lm_file    = "$cache_path/blocklist_$url_md5.lastmod";

            my ($etag, $lastmod);

            if ($use_cache && -f $etag_file) {
                if (open my $fh, '<', $etag_file) {
                    local $/;
                    $etag = <$fh>;
                    close $fh;
                    chomp($etag) if $etag;
                }
            }
            if ($use_cache && -f $lm_file) {
                if (open my $fh, '<', $lm_file) {
                    local $/;
                    $lastmod = <$fh>;
                    close $fh;
                    chomp($lastmod) if $lastmod;
                }
            }

            my $content;
            my $cache_is_fresh = 0;

            # Cache freshness check
            if ($use_cache && -f $cache_file) {
                my $mtime = (stat($cache_file))[9] || 0;
                my $age   = time() - $mtime;
                if ($age < $interval) {
                    $cache_is_fresh = 1;
                    $log->info("public_blocklist_thread: using fresh cached blocklist $cache_file (age=${age}s)");
                    $content = do {
                        local $/;
                        open my $fh, '<', $cache_file or do {
                            $log->warn("public_blocklist_thread: could not read cache file $cache_file: $!");
                            undef;
                        };
                        <$fh>;
                    };
                } else {
                    $log->info("public_blocklist_thread: cache stale for $url (age=${age}s), performing conditional HTTP GET");
                }
            }

            # Conditional GET if needed
            if (!$content) {
                my %headers;
                $headers{'If-None-Match'}     = $etag    if defined $etag    && length $etag;
                $headers{'If-Modified-Since'} = $lastmod if defined $lastmod && length $lastmod;

                $log->info("public_blocklist_thread: sending GET $url with headers: " . Dumper(\%headers));
                my $response = $ua->get($url, %headers);

                if ($response->code == 304) {
                    $log->info("public_blocklist_thread: 304 Not Modified for $url, using cached content");
                    $content = do {
                        local $/;
                        open my $fh, '<', $cache_file or do {
                            $log->warn("public_blocklist_thread: cache missing for $url despite 304; skipping");
                            next URL;
                        };
                        <$fh>;
                    };
                }
                elsif ($response->is_success) {
                    $content = $response->decoded_content;
                    if ($use_cache) {
                        if (open my $fh, '>', $cache_file) {
                            print {$fh} $content;
                            close $fh;
                        }
                        if (my $new_etag = $response->header('ETag')) {
                            if (open my $efh, '>', $etag_file) {
                                print {$efh} $new_etag;
                                close $efh;
                                $log->info("public_blocklist_thread: saved ETag for $url: $new_etag");
                            }
                        }
                        if (my $new_lm = $response->header('Last-Modified')) {
                            if (open my $lfh, '>', $lm_file) {
                                print {$lfh} $new_lm;
                                close $lfh;
                                $log->info("public_blocklist_thread: saved Last-Modified for $url: $new_lm");
                            }
                        }
                        $log->info("public_blocklist_thread: updated cache for $url");
                    }
                }
                else {
                    $log->warn("public_blocklist_thread: failed to fetch $url: " . $response->status_line);
                    if ($use_cache && -f $cache_file) {
                        $log->warn("public_blocklist_thread: using stale cache for $url due to error");
                        $content = do {
                            local $/;
                            open my $fh, '<', $cache_file;
                            <$fh>;
                        };
                    } else {
                        next URL;
                    }
                }
            }

            my %seen;
            while ($content =~ /($RE{net}{IPv4})(?:\/(\d{1,2}))?/g) {
                my $ip   = $1;
                my $mask = $2;
                my $entry = defined $mask ? "$ip/$mask" : $ip;
                $seen{$entry}++;
            }

            $log->info("public_blocklist_thread: blocklist ($url) contains " . scalar(keys %seen) . " entries");

            for my $entry (keys %seen) {
                next if _is_never_block_ip(ip => $entry, conf => $conf);
                $self->enqueue_ip(
                    ip       => $entry,
                    source   => 'public_blocklist',
                    detector => $url,
                    line     => undef,
                );
            }
        }

        for (1 .. $interval) {
            if ( $self->shutdown_check() ) {
                $log->debug("Spamhaus blocklist plugin shutting down as requested");
                last;
            }
            if ( $self->reload_check() ) {
                $log->debug("Spamhaus blocklist exitting for reload as requested");
                last;
            }
            sleep 1;
        }
    }

    $log->info("Spamhaus blocklist plugin exiting gracefully");
    Log::Log4perl::MDC->remove("THREAD");

    return 1;    
}

1;
