#!/usr/bin/perl

use strict;
use warnings;

use Net::Abuse::Utils qw( :all );

my %dnsbl = (
		'Spamhaus'      => 'sbl-xbl.spamhause.org',
		'SpamCop'       => 'bl.spamcop.net',
		'Relays ORDB'   => 'relays.ordb.org',
		'Relays VISI'   => 'relays.vsi.com',
		'Composite BL'  => 'cbl.abuseat.org',
		'Dynablock BL'  => 'dnsbl.njabl.org',
		'DSBL Proxy'    => 'list.dsbl.org',
		'DSBL Multihop' => 'multihop.dsbl.org',
		'SORBS OR'      => 'dnsbl.sorbs.net',
		'SPEWS L1'      => 'l1.spews.dnsbl.sorbs.net',
		'SPEWS L2'      => 'l2.spews.dnsbl.sorbs.net',
		'Blitzed OPM'   => 'opm.blitzed.org',
		);

my $ip = shift;

if (!is_ip($ip)) {
    warn "$ip doesn't look like an IP.\n";
    exit;
}


my $rdns = get_rdns($ip) || '';
print "IP Info:\n";
print "\tIP:         $ip\n";
print "\tRDNS:       $rdns\n";
print "\tIP Country: ", get_ip_country($ip), "\n";

print "\nAS Info:\n";
if (my @asn = get_asn_info($ip) ) {
    my $asn_org = get_as_description($asn[0]) || '';
    print "\tASN:        $asn[0] - $asn[1]\n";
    print "\tAS  Org:    $asn_org\n";
    print "\tAS Country: ", get_asn_country($asn[0]), "\n";
}
else {
    print "\tUnknown ASN\n";
}

print "\nDNSBL Listings:\n";
foreach my $bl (keys %dnsbl) {
    my $txt = get_dnsbl_listing($ip, $dnsbl{$bl}) || 'not listed';
    print "\t$bl:\t$txt\n";
}

my $soa_contact = get_soa_contact($ip) || 'not found';
print "\nContact Addresses:\n";
print "\tPTR SOA Contact: $soa_contact\n";
print "\tIP Whois Contacts: ", join (' ', get_ipwi_contacts($ip) ), "\n";

if ($soa_contact =~ /\@(\S+)$/) {
    print "\tAbuse.net ($1): ", get_abusenet_contact($1), "\n";
}
