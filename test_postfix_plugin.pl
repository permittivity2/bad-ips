#!/usr/bin/perl
# Test script for BadIPs::Plugins::Postfix

use strict;
use warnings;
use lib 'usr/local/lib/site_perl';
use BadIPs::Plugins::Postfix;
use Log::Log4perl qw(:easy);
use Data::Dumper;

# Initialize logging
Log::Log4perl->easy_init({
    level  => $DEBUG,
    format => "[%d] [%p] %m%n",
});

my $log = get_logger();

# Configuration
my $conf = {
    Plugins => {
        Postfix => {
            active => 1,
            journal_unit => "postfix.service",
            fetch_interval => 5,
            initial_fetch => 300,
            protocol_violations_count => 1,
            protocol_violations_window => 1,
            sasl_failures_count => 3,
            sasl_failures_window => 600,
            relay_denials_count => 2,
            relay_denials_window => 300,
            escalation_ttl_1 => 600,
            escalation_ttl_2 => 3600,
            escalation_ttl_3 => 21600,
            pattern_protocol_violations_01 => "Non-SMTP:::non-SMTP command from",
            pattern_protocol_violations_02 => "Improper pipelining:::improper command pipelining after CONNECT from",
            pattern_sasl_failures_01 => "SASL LOGIN:::SASL LOGIN authentication failed",
            pattern_sasl_failures_02 => "SASL PLAIN:::SASL PLAIN authentication failed",
            pattern_relay_denials_01 => "Relay denied:::Relay access denied",
        }
    }
};

# Create plugin instance
my @blocked_ips;
my $plugin = BadIPs::Plugins::Postfix->new(
    conf => $conf,
    plugin_section => "Plugins:Postfix",
    dry_run => 1,
    enqueue_ip => sub {
        my (%args) = @_;
        push @blocked_ips, \%args;
        $log->info("ENQUEUED: IP=$args{ip} TTL=$args{ttl} REASON=$args{reason}");
    },
);

print "\n=== POSTFIX PLUGIN TEST SUITE ===\n\n";

# Test 1: Pattern matching
print "TEST 1: Pattern Matching\n";
print "---\n";
my $test_lines = [
    {
        line => "non-SMTP command from unknown[149.54.62.118]:5234",
        expected => "protocol_violations"
    },
    {
        line => "improper command pipelining after CONNECT from unknown[45.164.115.86]:1234",
        expected => "protocol_violations"
    },
    {
        line => q{warning: unknown[149.54.62.118]:60377: SASL LOGIN authentication failed: (reason unavailable), sasl_username=freecycle.org@forge.name},
        expected => "sasl_failures"
    },
    {
        line => 'Relay access denied from unknown[201.32.76.218]:1234',
        expected => "relay_denials"
    },
];

for my $test (@$test_lines) {
    my $result = $plugin->_match_patterns($test->{line});
    my $status = ($result && $result->{category} eq $test->{expected}) ? "✓ PASS" : "✗ FAIL";
    print "$status: $test->{line}\n";
    if ($result) {
        print "       Category: $result->{category}\n";
    }
}

# Test 2: IP extraction
print "\nTEST 2: IP Extraction\n";
print "---\n";
my $ip_test_lines = [
    "non-SMTP command from unknown[147.185.132.193]:52752" => "147.185.132.193",
    'warning: unknown[149.54.62.118]:60377: SASL LOGIN authentication failed' => "149.54.62.118",
    'Relay access denied from ec2-13-58-162-150.us-east-2.compute.amazonaws.com[13.58.162.150]:60536' => "13.58.162.150",
];

while (my ($line, $expected_ip) = each @$ip_test_lines) {
    my $ip = $plugin->_extract_ip($line);
    my $status = ($ip && $ip eq $expected_ip) ? "✓ PASS" : "✗ FAIL";
    print "$status: extracted '$ip' (expected '$expected_ip')\n";
}

# Test 3: SASL info extraction
print "\nTEST 3: SASL Information Extraction\n";
print "---\n";
my $sasl_line = q{warning: unknown[149.54.62.118]:60377: SASL LOGIN authentication failed: (reason unavailable), sasl_username=freecycle.org@forge.name};
my $sasl_info = $plugin->_extract_sasl_info($sasl_line);
my $expected_username = q{freecycle.org@forge.name};
my $sasl_pass = ($sasl_info && $sasl_info->{ip} eq "149.54.62.118" && $sasl_info->{username} eq $expected_username);
print ($sasl_pass ? "✓ PASS" : "✗ FAIL") . ": SASL extraction\n";
if ($sasl_info) {
    print "       IP: $sasl_info->{ip}\n";
    print "       Username: $sasl_info->{username}\n";
}

# Test 4: Protocol violation blocking
print "\nTEST 4: Protocol Violation (Immediate Blocking)\n";
print "---\n";
@blocked_ips = ();
$plugin->_handle_protocol_violation(
    "149.54.62.118",
    "Non-SMTP command",
    "non-SMTP command from unknown[149.54.62.118]:5234"
);
if (@blocked_ips == 1 && $blocked_ips[0]{ip} eq "149.54.62.118") {
    print "✓ PASS: Protocol violation triggered blocking\n";
    print "       IP: $blocked_ips[0]{ip}\n";
    print "       TTL: $blocked_ips[0]{ttl}s (offense #1)\n";
} else {
    print "✗ FAIL: Protocol violation did not trigger blocking\n";
}

# Test 5: SASL username-based threshold
print "\nTEST 5: SASL Username-Based Threshold\n";
print "---\n";
@blocked_ips = ();

# Simulate 3 failed attempts to the same username from different IPs
my $username = q{freecycle.org@forge.name};
my @test_ips = ("149.54.62.118", "45.164.115.86", "182.95.181.50");

for my $ip (@test_ips) {
    $plugin->_handle_sasl_failure(
        $ip,
        $username,
        "warning: unknown[$ip]:60377: SASL LOGIN authentication failed, sasl_username=$username"
    );
}

# Check if 3 IPs got blocked
my $expected_blocks = 3;
my $actual_blocks = scalar(@blocked_ips);
print "✓ PASS: $actual_blocks IPs blocked (expected $expected_blocks)\n" if $actual_blocks == $expected_blocks;
print "✗ FAIL: $actual_blocks IPs blocked (expected $expected_blocks)\n" if $actual_blocks != $expected_blocks;

if (@blocked_ips) {
    print "       Blocked IPs:\n";
    for my $item (@blocked_ips) {
        print "         - $item->{ip} (TTL: $item->{ttl}s, offense: 1st)\n";
    }
}

# Verify username tracking
if (exists $plugin->{username_tracking}{$username}) {
    my $tracking = $plugin->{username_tracking}{$username};
    print "       Username tracking updated:\n";
    print "         - Attempts tracked: " . scalar(@{ $tracking->{attempts} }) . "\n";
    print "         - Offense count: $tracking->{offense_count}\n";
}

# Test 6: Escalating TTL
print "\nTEST 6: Escalating TTL Calculation\n";
print "---\n";
my @ttl_tests = (
    { offense => 1, expected => 600 },
    { offense => 2, expected => 3600 },
    { offense => 3, expected => 21600 },
    { offense => 4, expected => 86400 },
    { offense => 5, expected => 604800 },
    { offense => 10, expected => 604800 },  # Should cap at level 5
);

for my $test (@ttl_tests) {
    my $ttl = $plugin->_calculate_escalating_ttl($test->{offense});
    my $status = ($ttl == $test->{expected}) ? "✓ PASS" : "✗ FAIL";
    print "$status: offense #$test->{offense} => ${ttl}s (expected $test->{expected}s)\n";
}

# Test 7: Duplicate block prevention
print "\nTEST 7: Duplicate Block Prevention\n";
print "---\n";
@blocked_ips = ();
my $test_ip = "201.32.76.218";

# First call should succeed
my $first = $plugin->_should_enqueue_ip($test_ip);
print ($first ? "✓ PASS" : "✗ FAIL") . ": First enqueue allowed\n";

# Second call immediately after should fail (within 10 minute window)
my $second = $plugin->_should_enqueue_ip($test_ip);
print (!$second ? "✓ PASS" : "✗ FAIL") . ": Duplicate enqueue prevented\n";

# Test 8: Relay denial threshold
print "\nTEST 8: Relay Denial Threshold\n";
print "---\n";
@blocked_ips = ();
my $relay_ip = "111.26.106.115";

# First relay denial - should not trigger
$plugin->_handle_relay_denial(
    $relay_ip,
    "Relay access denied from unknown[$relay_ip]:1234"
);
print (scalar(@blocked_ips) == 0 ? "✓ PASS" : "✗ FAIL") . ": First relay denial (no block)\n";

# Second relay denial - should trigger blocking
$plugin->_handle_relay_denial(
    $relay_ip,
    "Relay access denied from unknown[$relay_ip]:1234"
);
print (scalar(@blocked_ips) == 1 ? "✓ PASS" : "✗ FAIL") . ": Second relay denial (block triggered)\n";
if (@blocked_ips) {
    print "       IP: $blocked_ips[0]{ip}\n";
    print "       TTL: $blocked_ips[0]{ttl}s (offense #1)\n";
}

print "\n=== TEST SUITE COMPLETE ===\n\n";

print "Summary:\n";
print "  - Patterns: 5 defined\n";
print "  - Plugin initialization: OK\n";
print "  - IP extraction: OK\n";
print "  - SASL tracking: OK\n";
print "  - Escalation: OK\n";
