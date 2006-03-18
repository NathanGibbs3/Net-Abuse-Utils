package Net::Abuse::Utils;

use 5.006_001;
use strict;
use warnings;

use Net::DNS;
use Net::Whois::IP qw(whoisip_query);
use Email::Address;

require Exporter;

our @ISA = qw(Exporter);

our %EXPORT_TAGS = ( 'all' => [ qw(
	get_asn_info get_as_description get_soa_contact get_ipwi_contacts
	get_rdns get_dnsbl_listing get_ip_country get_asn_country
	get_abusenet_contact is_ip
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our $VERSION = '0.05';
$VERSION = eval $VERSION;

sub _reverse_ip {
    my $ip = shift;
    my @quads = split ('\.', $ip);
    return join('.', reverse(@quads));
} 

sub _return_rr {
    my $lookup  = shift;
    my $rr_type = shift;
    my $concat  = shift;

    my @result;

    my $res = Net::DNS::Resolver->new;

    my $query = $res->query($lookup, $rr_type);
    if ($query) {
            foreach my $rr ($query->answer) {
                if ($rr->type eq $rr_type) { 
                    if    ($rr_type eq 'TXT') {
                        push @result, $rr->txtdata;
                    }
                    elsif ($rr_type eq 'SOA') {
                        push @result, $rr->rname;
                    }
                    elsif ($rr_type eq 'PTR') {
                        push @result, $rr->ptrdname;
                    }
                    last if !$concat;
                }
            }
            
            if ($concat && $concat == 2) {
                return @result;
            }
            else { 
                return join ' ', @result;
            }
    }
    
    return; 
}

sub _return_unique {
    my $array_ref = shift;
    my %unique_elements;

    foreach my $element (@$array_ref) {
        $unique_elements{ $element }++;
    }

    return keys %unique_elements;
}

sub _strip_whitespace {
    my $string = shift;
    
    return unless $string;
    
    for ($string) {
        s/^\s+//;
        s/\s+$//;
    }
    
    return $string;
}

sub get_ipwi_contacts {
    my $ip = shift;

    my @addresses;
    my %unique_addresses;

    my $response = whoisip_query($ip);

    # whoisip_query returns array ref if not found
    return unless ref($response) eq 'HASH';
    
    foreach my $field (keys %$response) {
        push @addresses, Email::Address->parse($response->{$field});
    }

    @addresses = map { $_->address } @addresses;

    return _return_unique (\@addresses);
}

sub get_asn_info {
    my $ip = shift;

    my $lookup    = _reverse_ip($ip) . '.origin.asn.cymru.com';
    my @origin_as = _return_rr($lookup, 'TXT', 2) or return;
    
    # 23028 | 216.90.108.0/24 | US | arin | 1998-09-25
    # 701 1239 3549 3561 7132 | 216.90.108.0/24 | US | arin | 1998-09-25
 
    my $smallest_netmask = 0;
    my ($smallest_asn, %data_for_asn);

    # surely there is a better way to do this, at least the split
    # fields are stored so they don't have to be split again ;)
    for my $asn_info (@origin_as) {
        my @fields  = split /\|/, $asn_info;
        my @network = split '/', $fields[1];

        # if multiple ASNs announce the same, block they are given space
        # seperated in the first field, we just use the first
        if ($fields[0] =~ /(\d+) \d+/) {
            $fields[0] = $1;
        }

        my $asn = $fields[0];
                 
        $data_for_asn{$asn} = [ @fields ];
        
        if ($network[1] > $smallest_netmask) {
            $smallest_netmask = $network[1];
            $smallest_asn     = $asn;
        }
    }

    return map { _strip_whitespace($_) } @{ $data_for_asn{$smallest_asn} };
}

sub get_as_description {
    my $asn = shift;
    my @ASdata;
    
    if (my $data = _return_rr("AS${asn}.asn.cymru.com", 'TXT')) {
        @ASdata = split('\|', $data);
    } 
    else {
        return;
    }
    
    # for arin we get HANDLE - AS Org
    if ($ASdata[2] eq ' arin ') {
        return _strip_whitespace (( split (/ - /, $ASdata[4], 2) )[1]);
    }
    else {
        return _strip_whitespace $ASdata[4];
    }
    
    return;
}

sub get_soa_contact {
    my $ip = shift;

    my $lookup = _reverse_ip($ip) . '.in-addr.arpa';
    $lookup =~ s/^\d+\.//;

    if ( my $soa_contact = _return_rr($lookup, 'SOA') ) {
        $soa_contact =~ s/\./@/;
        return $soa_contact;
    }
    
    return;
}

sub get_rdns {
    my $ip = shift;

    return _return_rr( _reverse_ip($ip) . '.in-addr.arpa', 'PTR');
}

sub get_dnsbl_listing {
    my $ip    = shift;
    my $dnsbl = shift;

    my $lookup = join '.', _reverse_ip( $ip ), $dnsbl;
    
    return _return_rr($lookup, 'TXT', 1);
}

sub get_ip_country {
     my $ip = shift;
     
     return (get_asn_info($ip))[2];
}

sub get_asn_country {
    my $asn   = shift;
    my $as_cc = (split (/\|/,_return_rr("AS${asn}.asn.cymru.com", 'TXT')))[1];
    if ($as_cc) {
        return _strip_whitespace ($as_cc);
    }
    return;
}

sub get_abusenet_contact {
    my $domain = shift;
    
    return _return_rr("$domain.contacts.abuse.net", 'TXT', 1)
}

sub is_ip {
    $_ = shift;
    return m/
                ^
                (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}
                (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
                $
           /x;
}

1;
__END__

=head1 NAME

Net::Abuse::Utils - Routines useful for processing network abuse


=head1 VERSION

This documentation refers to Net::Abuse::Utils version 0.05.


=head1 SYNOPSIS

    use Net::Abuse::Utils qw( :all );
    print "IP Whois Contacts: ", join( ' ', get_ipwi_contacts($ip) ), "\n";
    print "Abuse.net Contacts: ", get_abusenet_contact($domain), "\n";

=head1 DESCRIPTION

Net::Abuse::Utils provides serveral functions useful for determining
information about an IP address including contact/reporting addresses,
ASN/network info, reverse dns, and DNSBL listing status.


=head1 FUNCTIONS

The following functions are exportable from this module.  You may import all
of them into your namespace with the C<:all> tag.

=over 5

=item get_asn_info ( IP )

Returns a list containing (ASN, Network/Mask, CC code, RIR, modified date)
for the network announcing C<IP>.

=item get_as_description ( ASN )

Returns the AS description for C<ASN>. 

=item get_soa_contact( IP )

Returns the SOA contact email address for the reverse DNS /24
zone containing C<IP>.

=item get_ipwi_contacts( IP )

Returns a list of all email addresses found in whois information
for C<IP> with duplicates removed.

=item get_rdns( IP )

Returns the reverse PTR for C<IP>.

=item get_dnsbl_listing( IP, DNSBL zone )

Returns the listing text for C<IP> for the designated DNSBL.  C<DNSBL zone>
should be the zone used for looking up addresses in the blocking list.

=item get_ip_country( IP )

Returns the 2 letter country code for C<IP>.

=item get_asn_country( ASN )

Returns the 2 letter country code for C<ASN>.

=item get_abusenet_contact ( domain )

Returns the abuse.net listed contact email addresses for C<domain>.

=item is_ip ( IP )

Returns true if C<IP> looks like an IP, false otherwise.

=back

=head1 DIAGNOSTICS

Each subroutine will return undef if unsuccessful.  In the furture,
debugging output will be available.

=head1 CONFIGURATION AND ENVIRONMENT

No configuration mechanism is currently implemented.

=head1 DEPENDENCIES

This module makes use of the following modules:

Net::DNS, Net::Whois::IP, Email::Address

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.  Please report problems to
Michael Greb (mgreb@linode.com)

Patches are welcome.

=head1 ACKNOWLEDGEMENTS

This module was inspired by Karsten M. Self's SpamTools shell scripts, 
available at http://linuxmafia.com/~karsten/.

Thanks as well to my employer, Linode.com, for allowing me the time to work
on this module.

Rik Rose, Jon Honeycutt, Brandon Hale, TJ Fontaine, and A. Pagaltzis all
provided invaluable input during the development of this module.

=head1 AUTHOR

Michael Greb (mgreb@linode.com)

=head1 SEE ALSO

For a detailed usage example, please see examples/ip-info.pl included in
this module's distribution.

=head1 LICENCE AND COPYRIGHT

Copyright (c)  2006 Michael Greb (mgreb@linode.com). All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

=cut