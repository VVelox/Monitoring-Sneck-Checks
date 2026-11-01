#!perl
use 5.014;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Monitoring::Sneck::Checks;

my $dir   = tempdir( CLEANUP => 1 );
my $write = sub {
	my ( $name, $content ) = @_;
	open( my $fh, '>', $dir . '/' . $name ) or die($!);
	print $fh $content;
	close($fh);
	return $dir . '/' . $name;
};
my $run = sub { return Monitoring::Sneck::Checks->run( check => 'config_value', args => [@_] ) };

my $login_defs = $write->(
	'login.defs',
	"# login.defs\nPASS_MAX_DAYS\t99999\nPASS_MIN_DAYS 1 # at least a day\nUMASK\t\t022\nENCRYPT_METHOD YESCRYPT\n"
);
is(
	$run->(
		'-f', $login_defs,                      '-e', 'PASS_MIN_DAYS>=1',
		'-e', 'encrypt_method=sha512|yescrypt', '-e', 'UMASK=022|027'
	)->{stdout},
	"CONFIG_VALUE OK - PASS_MIN_DAYS 1, encrypt_method YESCRYPT, UMASK 022\n",
	'spaces, comments, no case'
);
is(
	$run->( '-f', $login_defs, '-e', 'PASS_MAX_DAYS<=365', '-e', 'LOGIN_RETRIES<=5', '-e', 'UMASK!=022' )->{stdout},
	"CONFIG_VALUE CRITICAL - PASS_MAX_DAYS is 99999, wanted at most 365, LOGIN_RETRIES is not set, UMASK is 022, wanted anything but 022\n",
	'not as wanted'
);
is( $run->( '-f', $login_defs, '-e', 'LOGIN_RETRIES<=5', '-d', 'LOGIN_RETRIES=5' )->{stdout},
	"CONFIG_VALUE OK - LOGIN_RETRIES 5 by default\n", '--default' );

my $rc_conf = $write->(
	'rc.conf', qq{sshd_enable="YES"\nsendmail_enable="NONE"\nifconfig_em0="inet 192.0.2.10/24"\nsshd_enable="NO"\n}
);
is(
	$run->( '-f', $rc_conf, '-S', '=', '-e', 'sendmail_enable=NO|NONE', '-e', 'ifconfig_em0=inet 192.0.2.10/24' )
		->{code},
	0,
	'rc.conf, quotes dropped'
);
is(
	$run->( '-f', $rc_conf, '-S', '=', '-e', 'sshd_enable=YES' )->{stdout},
	"CONFIG_VALUE CRITICAL - sshd_enable is NO, wanted YES\n",
	'the last wins'
);
is( $run->( '-f', $rc_conf, '-S', '=', '-e', 'sshd_enable=YES', '-F' )->{code}, 0, '--first' );
is(
	$run->( '-f', $rc_conf, '-S', '=', '-e', 'sshd_enable=no', '-C' )->{stdout},
	"CONFIG_VALUE CRITICAL - sshd_enable is NO, wanted no\n",
	'--case-sensitive'
);
is(
	$run->( '-f', $rc_conf, '-S', '=', '-e', 'SSHD_ENABLE=NO', '-C' )->{stdout},
	"CONFIG_VALUE CRITICAL - SSHD_ENABLE is not set\n",
	'names with case'
);

my $sysctl_conf = $write->( 'sysctl.conf', "net.ipv4.ip_forward = 1\nkernel.randomize_va_space=2\n" );
is(
	$run->( '-f', $sysctl_conf, '-S', '=', '-e', 'net.ipv4.ip_forward=0', '-e', 'kernel.randomize_va_space=2' )
		->{stdout},
	"CONFIG_VALUE CRITICAL - net.ipv4.ip_forward is 1, wanted 0\n",
	'sysctl.conf'
);

like( $run->( '-f', $dir . '/nope', '-e', 'a=b' )->{stdout},
	qr/\ACONFIG_VALUE CRITICAL - can not read \S+nope/, 'missing' );
foreach my $bad (
	[ '-f', $login_defs ],
	[ '-f', $login_defs, '-e', 'x' ],
	[ '-f', $login_defs, '-e', 'x>y' ],
	[ '-f', $login_defs, '-e', 'x=1', '-S', '' ]
	)
{
	is( $run->( @{$bad} )->{code}, 3, 'bad args, ' . join( ' ', @{$bad} ) );
}

done_testing();
