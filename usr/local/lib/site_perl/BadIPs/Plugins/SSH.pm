package BadIPs::Plugins::SSH;

use strict;
use warnings;

my $log = Log::Log4perl::get_logger("BadIPs::Plugins::SSH");

=head1 NAME

BadIPs::Plugins::SSH - Plugin to monitor SSH logs for failed login attempts

This really just calls GeneralLogMonitor with the SSH-specific configuration.
=cut

sub new {
    my ($class, %args) = @_;

    # Create GeneralLogMonitor instance with SSH-specific config
    require BadIPs::Plugins::GeneralLogMonitor;
    my $gl_monitor = BadIPs::Plugins::GeneralLogMonitor->new(
        conf           => $args{conf},
        dry_run        => $args{dry_run} || 0,
        log            => $args{log} || $args{log} || get_logger(__PACKAGE__),
        reload_check   => $args{reload_check},
        shutdown_check => $args{shutdown_check},
        enqueue_ip     => $args{enqueue_ip},
        plugin_name    => 'SSH',
    );

    bless $gl_monitor, $class;
    return $gl_monitor;
}

1;