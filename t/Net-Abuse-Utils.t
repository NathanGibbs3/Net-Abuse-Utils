BEGIN {
    unless ($ENV{RELEASE_TESTING} || $ENV{ONLINE_TESTS}) {
        require Test::More;
        Test::More::plan(skip_all=>'these online tests require env variable ONLINE_TESTS be set to run');
    }
}

use Test::More;
BEGIN { use_ok('Net::Abuse::Utils') };

#########################

use Net::Abuse::Utils qw ( :all );

# these depend on network access, silly I know
# future versions will override the modules used by Net::Abuse::Utils
# to hand it static data

my $ip = '67.18.92.99';
is ( get_abusenet_contact('linode.com') , 'abuse@linode.com',   'abuse.net lookup'      );
is ( get_soa_contact('209.123.233.241') , 'dnsadmin@nac.net',   'soa contact'           );
is ( get_ip_country($ip)                , 'US',                 'IP Country lookup'     );
is ( get_ip_country('2600:3c00::2:200') , 'US',                 'IPv6 Country lookup'   );
ok ( !get_ip_country('127.0.0.1'),                              'IP Country lookup with bad ip');
is ( get_rdns($ip)                      , 'mail.linode.com',    'get_rdns'              );
ok ( (get_asn_info($ip))[0]             =~ /^\d+$/,             'ASN from IP'           );
is ( get_asn_country(21844)             , 'US',                 'AS Country lookup'     );
ok ( !get_asn_country('urmom'),                                 'AS Country lookup w/ invalid ASN');
is ( get_as_description(21844)          , 'THEPLANET-AS ThePlanet.com Internet Services, Inc.', 'AS Description' );
is ( get_as_company(21844)              , 'ThePlanet.com Internet Services, Inc.', 'AS Company' );
is ( get_domain('some.co.uk')           , 'some.co.uk',         'get_domain'            );
is ( get_domain('host.some.co.uk')      , 'some.co.uk',         'get_domain'            );
is ( get_domain('some.com')             , 'some.com',           'get_domain'            );
is ( get_domain('host.some.com')        , 'some.com',           'get_domain'            );
ok ( get_dnsbl_listing('127.0.0.2', 'bl.spamcop.net'),          'DNSBL listing check'   );

like ( join(' ',get_ipwi_contacts('67.18.92.99')), qr/\w+@\w+/, 'whois contacts');

push @Net::Abuse::Utils::RESOLVERS, '0.0.0.0';
$ENV{RES_OPTIONS} = 'retrans:1 retry:1'; # fail fast with invalid rsolver ip
Net::DNS::Resolver->read_env();
is ( get_ip_country($ip)                , undef,                 '@RESOLVERS is used'   );
@Net::Abuse::Utils::RESOLVERS = ();

done_testing;
