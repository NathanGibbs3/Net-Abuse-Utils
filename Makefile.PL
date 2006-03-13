use 5.008007;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Net::Abuse::Utils',
    VERSION_FROM      => 'lib/Net/Abuse/Utils.pm',
    PREREQ_PM         => {
							Net::DNS => 0,
							Net::Whois::IP => 0,
 							Email::Address => 0,
						 },
    ($] >= 5.005 ?
      	(ABSTRACT_FROM  => 'lib/Net/Abuse/Utils.pm',
       	 AUTHOR         => 'Michael Greb <mikegrb@cpan.org>')
	:
		()
	),
);