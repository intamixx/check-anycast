#!/usr/bin/perl

# Msingh 08/14
# To check response of anycast nameservers on cloud A and B, by querying the unicast address
# requires "perl-IO-Socket-INET6.noarch"

use warnings;
use strict;
use Net::DNS;
use Getopt::Long;

# options
#  -s                summary
#  -d                debug
#  -n <nameserver>   nameserver to query
#  -4		     ipv4 mode
#  -6		     ipv6 mode

# Example usage - "./check_anycast -d -4 -n ns0.test.net"

usage() if (!@ARGV);

my( @opts_s, @opts_d, @opts_h, @opts_4, @opts_6, @opts_n );

GetOptions(
           's' => \@opts_s,
           'd' => \@opts_d,
           'h' => \@opts_h,
           '4' => \@opts_4,
           '6' => \@opts_6,
           'n=s{1,9}' => \@opts_n,
          );

usage() if @opts_h;

if ( (@opts_4) && (@opts_6) ) {
	print "Please specify either ipv4 or ipv6\n";
	exit 3;
	}

if ( !(@opts_4) && !(@opts_6) ) {
	print "Must specify one mode: -4  or -6\n";
	exit 3;
	}

if ( !(@opts_n) ) {
	print "Must specify a nameserver to query\n";
	exit 3;
	}

my $timeout=10;
# Change this setting if checking for another zone
my $domain = "test.net";
my $cloudAsrvq = "_dns._udp.a.dns.test.net";
my $cloudBsrvq = "_dns._udp.b.dns.test.net";

# servers to check for domain records
#my @servers = qw(ns0.test.net);
#my @servers = qw(2a01:300:54::2);
my @servers = @opts_n;

# Initialise the hash array for anycast servers and ids
my %anycast = ();

print STDERR "---------\n" if @opts_d;
print STDERR "Checking DNS, please wait...\n" if @opts_d;
# Lets find out which servers knows about test.net
my %results;
foreach my $server (@servers) {
    $results{$server} 
        = lookup( $domain, $server );
}

        print STDERR "---------\n" if @opts_d;

# Delete a server from hash that did not respond to dns request

foreach my $ns ( sort keys %results ) {
        delete $results{$ns} if not defined $results{$ns};
#       print STDERR "$ns / $results{$ns}\n" if defined $results{$ns} if @opts_d;
        }

# Select server, choose first one

if ( %results ) {
        print STDERR "Selecting nameserver... " if @opts_d;
        my @dns = sort keys(%results);
        my $dns = $dns[0];
        print STDERR "Choosing $dns\n" if @opts_d;

        print STDERR "---------\n" if @opts_d;
        print STDERR "Anycast servers Cloud A\n" if @opts_d;

        my $cloudAresults;
        $cloudAresults = SRVquery ( $cloudAsrvq, $dns );
                if ($cloudAresults) {
                        printf ("%s cloud A NOTOK: %s\n", $domain, $cloudAresults) if @opts_s;
                } else {
                        printf ("%s cloud A OK\n", $domain, $cloudAresults) if @opts_s;
                }

        my $nameservers;
        # Clean the nameserver list
        @{$nameservers} = ();

        print STDERR "---------\n" if @opts_d;
        print STDERR "Anycast servers Cloud B\n" if @opts_d;

        my $cloudBresults;
        $cloudBresults = SRVquery ( $cloudBsrvq, $dns );
                if ($cloudBresults) {
                        printf ("%s cloud B NOTOK: %s\n", $domain, $cloudBresults) if @opts_s;
                } else {
                        printf ("%s cloud B OK\n", $domain, $cloudBresults) if @opts_s;
                }

        print STDERR "---------\n" if @opts_d;

        } else {

        printf ("Nameservers %s contained no information about $domain. Check script config.\n", join (' ', @servers)) if @opts_d || @opts_s;
        exit;
        }

sub SRVquery {

    my ( $srvquery, $dns ) = @_;
    my $nameservers;
    my $ns;
    my $badns = [];

    my %anycast = ();
    my $family;
    my $i;

# Run the SRV query to get list of anycast nameservers against chosen authorative server
print STDERR "---------\n" if @opts_d;

        my $res = Net::DNS::Resolver->new( nameservers => [$dns], tcp_timeout => $timeout, udp_timeout => $timeout );
        my $query = $res->query($srvquery, 'SRV');

                if ( !$query ) {
                        warn " *** Query failed: ", $res->errorstring, " ***\n" if @opts_d;
                } else {

                        foreach my $rr (grep{ $_->type eq 'SRV' }$query->answer) {
				push( @{$nameservers}, $rr->target );
                        }

			# Get IPv4 and IPv6 information and insert into hash of arrays: $anycast = ( nameserver => [ ip4/6 ] )
                        foreach $ns ( sort @{$nameservers}) {
				if (@opts_4) {
					my $query = $res->query("$ns", "A");
					if ($query) {
						foreach my $rr (grep { $_->type eq 'A' } $query->answer) {
                                			push(@{$anycast{$ns}}, $rr->address);
						}
					} else {
                                			push(@{$anycast{$ns}}, "");
							warn " *** $ns A query failed: ", $res->errorstring, " ***\n" if @opts_d;
					}
				}
				if (@opts_6) {
					my $query = $res->query("$ns", "AAAA");
					if ($query) {
						foreach my $rr (grep { $_->type eq 'AAAA' } $query->answer) {
                                			push(@{$anycast{$ns}}, $rr->address);
						}
					} else {
                                			push(@{$anycast{$ns}}, "");
							warn " *** $ns AAAA query failed: ", $res->errorstring, " ***\n" if @opts_d;
					}
				}
			}

                        foreach $ns ( sort keys %anycast ) {
                        # Set the resolver to query this nameserver
                        $res->nameservers($anycast{$ns}[0]) if @opts_4;
                        $res->nameservers($anycast{$ns}[0]) if @opts_6;
                        $query = $res->send('id.server' , 'TXT', 'CH');
                                if ( !$query ) {
                                        warn " *** ", $ns, " NO response to server-id request! ***\n" if @opts_d;
                                        push(@{$badns}, $ns );
                                        next;
                                        } else {
                                        printf STDERR ("%s", $ns) if @opts_d;
                                        foreach my $rr ( grep{ $_->type eq 'TXT' }$query->answer) {
                                                if ($rr->txtdata =~ /(\.*)/) {
                                                        printf STDERR ("(%s) -> %s\n", $res->answerfrom, $rr->txtdata) if @opts_d;
                                                        last;
                                                }
                                        }
                                }
                        }
                }
        return join( ' ', sort @{$badns} );
}

sub lookup {
    my ( $domain, $server ) = @_;

    my (@results);
    my $res = Net::DNS::Resolver->new( tcp_timeout => $timeout, udp_timeout => $timeout);

    $res->nameservers($server);
    my $packet = $res->query($domain, "A");

    if ( !$packet ) {
        warn "Nameserver $server - $domain dns zone NOTOK\n" if @opts_d;
        return;
    } else {
        print STDERR "Nameserver $server - $domain dns zone OK\n" if @opts_d;
        }
    foreach my $rr ( $packet->answer ) {
        push ( @results, $rr->address );
    }
    return join( ', ', sort @results );
}

sub usage {
        print STDERR "usage: $0 [-d][-s][-4/-6][-n domain]\n";
        print STDERR "  -s               summary\n";
        print STDERR "  -d               debug\n";
	print STDERR "  -n <nameserver>  nameserver to query\n";
	print STDERR "  -4               ipv4 mode\n";
	print STDERR "  -6               ipv6 mode\n";
        exit 3;
}
