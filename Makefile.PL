use 5.006001;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    (MM->can('signature_target') ? (SIGN => 1) : ()),
    NAME              => 'Net::Abuse::Utils',
    AUTHOR            => 'Michael Greb <mgreb@linode.com>',
    VERSION_FROM      => 'lib/Net/Abuse/Utils.pm',
    ABSTRACT_FROM     => 'lib/Net/Abuse/Utils.pm',
    LICENSE           => 'perl',
    PREREQ_PM         => {
							Net::DNS => 0,
							Net::Whois::IP => 0,
							Email::Address => 0,
							perl => 5.006,
    },
);