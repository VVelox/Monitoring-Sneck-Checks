#!perl
use 5.014;
use strict;
use warnings;
use FindBin;
use lib $FindBin::Bin . '/lib';
use Test::More;
use TestTmp;
use File::Path qw(make_path);
use Monitoring::Sneck::Checks;
use Monitoring::Sneck::Checks::base;
use Monitoring::Sneck::Checks::kernel_modules;
use Monitoring::Sneck::Checks::packages;
use Monitoring::Sneck::Checks::accounts;

my $dir   = TestTmp::dir();
my $write = sub {
	my ( $name, $content ) = @_;
	my $path = $dir . '/' . $name;
	make_path( $path =~ s{/[^/]+\z}{}r );
	open( my $fh, '>', $path ) or die($!);
	print $fh $content;
	close($fh);
	return $path;
};
local $Monitoring::Sneck::Checks::base::OS   = 'linux';
local $Monitoring::Sneck::Checks::base::PROC = $dir . '/proc';
my $run = sub {
	my ( $check, @args ) = @_;
	return Monitoring::Sneck::Checks->run( check => $check, args => \@args );
};
my %sysctl;
{
	no warnings 'once';
	$INC{'BSD/Sysctl.pm'} = __FILE__;
	*BSD::Sysctl::sysctl = sub { return $sysctl{ $_[0] } };
}

# sysctl
$write->( 'proc/sys/kernel/randomize_va_space',         "2\n" );
$write->( 'proc/sys/net/ipv4/ip_forward',               "0\n" );
$write->( 'proc/sys/net/ipv4/ip_local_port_range',      "32768\t60999\n" );
$write->( 'proc/sys/net/ipv4/conf/eth0.100/forwarding', "1\n" );
my $return = $run->(
	'sysctl', '-e', 'kernel.randomize_va_space=2', '-e',
	'net.ipv4.ip_forward=0|2', '-e', 'net.ipv4.ip_local_port_range=32768 60999'
);
is( $return->{code}, 0, 'as wanted' );
is(
	$return->{stdout},
	"SYSCTL OK - kernel.randomize_va_space 2, net.ipv4.ip_forward 0, net.ipv4.ip_local_port_range 32768 60999\n",
	'output, tabs squashed'
);
is(
	$run->(
		'sysctl',                 '-e', 'kernel.randomize_va_space!=2', '-e',
		'net.ipv4.ip_forward>=1', '-e', 'kernel.nope=1',                '-e',
		'net/ipv4/conf/eth0.100/forwarding=0'
	)->{stdout},
	"SYSCTL CRITICAL - kernel.randomize_va_space is 2, wanted anything but 2, net.ipv4.ip_forward is 0, wanted at least 1, kernel.nope is not there, net/ipv4/conf/eth0.100/forwarding is 1, wanted 0\n",
	'not as wanted, a / name'
);
is( $run->( 'sysctl', '-e', 'kernel.nope=1', '-m' )->{stdout}, "SYSCTL OK - none of them are there\n", '--missing-ok' );
$write->( 'proc/sys/kernel/empty', "\n" );
is( $run->( 'sysctl', '-e', 'kernel.empty=' )->{stdout}, "SYSCTL OK - kernel.empty \"\"\n", 'a empty value wanted' );
is(
	$run->( 'sysctl', '-e', 'kernel.empty=x' )->{stdout},
	"SYSCTL CRITICAL - kernel.empty is \"\", wanted x\n",
	'a empty value not wanted'
);
is(
	$run->( 'sysctl', '-e', 'net/../../../etc/passwd=1' )->{stdout},
	"SYSCTL CRITICAL - net/../../../etc/passwd is not there\n",
	'.. not followed'
);

foreach my $bad ( ['-e'], [ '-e', 'kernel.x' ], [ '-e', 'kernel.x>=abc' ] ) {
	is( $run->( 'sysctl', @{$bad} )->{code}, 3, 'bad args, ' . join( ' ', @{$bad} ) );
}
{
	local $Monitoring::Sneck::Checks::base::OS = 'freebsd';
	%sysctl = ( 'kern.securelevel' => -1, 'vm.loadavg' => [ 1, 2, 3 ] );
	is( $run->( 'sysctl', '-e', 'kern.securelevel>=1' )->{stdout},
		"SYSCTL CRITICAL - kern.securelevel is -1, wanted at least 1\n", 'FreeBSD' );
	is( $run->( 'sysctl', '-e', 'vm.loadavg=1 2 3' )->{code}, 0, 'FreeBSD array values' );
}

# kernel_modules
$write->(
	'proc/modules',
	"ext4 1081344 2 - Live 0x0000000000000000\nusb_storage 77824 0 - Live 0x0000000000000000\ndccp 90112 0 - Live 0x0\n"
);
$write->( 'modules/6.12.48/modules.builtin', "kernel/fs/vfat/vfat.ko\nkernel/drivers/block/loop.ko\n" );
$write->( 'modprobe.d/cis.conf',             "install cramfs /bin/false\nblacklist cramfs\ninstall udf /bin/true\n" );
local $Monitoring::Sneck::Checks::kernel_modules::MODULES       = $dir . '/modules';
local $Monitoring::Sneck::Checks::kernel_modules::RELEASE       = '6.12.48';
local @Monitoring::Sneck::Checks::kernel_modules::MODPROBE_DIRS = ( $dir . '/modprobe.d', $dir . '/nope.d' );
$return = $run->( 'kernel_modules', '-p', 'ext4', '-p', 'loop', '-a', 'firewire-core', '-n', 'cramfs', '-n', 'udf' );
is( $return->{code}, 0, 'as wanted' );
is(
	$return->{stdout},
	"KERNEL_MODULES OK - ext4 loaded, loop loaded, firewire-core not loaded, cramfs not loadable, udf not loadable\n",
	'output, built in counts'
);
is(
	$run->( 'kernel_modules', '-p', 'zfs', '-a', 'usb-storage', '-a', 'vfat', '-n', 'dccp' )->{stdout},
	"KERNEL_MODULES CRITICAL - zfs is not loaded, usb-storage is loaded, vfat is built in, dccp is loaded and is not kept from loading by a install line in modprobe.d\n",
	'not as wanted, - and _ the same'
);
is( $run->('kernel_modules')->{code}, 3, 'nothing to check' );
{
	local $Monitoring::Sneck::Checks::base::OS = 'freebsd';
	local $Monitoring::Sneck::Checks::kernel_modules::KLDSTAT
		= $write->( 'kldstat', '#!' . $^X . "\nexit( \$ARGV[2] eq 'zfs' ? 0 : 1 );\n" );
	chmod( 0755, $dir . '/kldstat' );
	is( $run->( 'kernel_modules', '-p', 'zfs', '-a', 'ipfw' )->{stdout},
		"KERNEL_MODULES OK - zfs loaded, ipfw not loaded\n", 'FreeBSD' );
	like(
		$run->( 'kernel_modules', '-n', 'ipfw' )->{stderr},
		qr/--not-loadable is not supported on freebsd/,
		'FreeBSD --not-loadable'
	);
}

# packages
local $Monitoring::Sneck::Checks::packages::DPKG_STATUS = $write->( 'dpkg/status', <<'END' );
Package: openssh-server
Status: install ok installed
Version: 1:10.0p1-7

Package: telnet
Status: deinstall ok config-files
Version: 0.17+2.4-2

Package: libc6
Status: hold ok installed
Architecture: amd64
Version: 2.41-12
END
is(
	$run->( 'packages', '-i', 'openssh-server', '-i', 'libc6', '-a', 'telnet', '-a', 'rsh-client' )->{stdout},
	"PACKAGES OK - openssh-server installed, libc6 installed, telnet not installed, rsh-client not installed\n",
	'dpkg, held counts, config files do not'
);
is(
	$run->( 'packages', '-i', 'auditd', '-a', 'openssh-server' )->{stdout},
	"PACKAGES CRITICAL - auditd is not installed, openssh-server is installed\n",
	'not as wanted'
);
like( $run->( 'packages', '-i', 'x', '-j', 'www' )->{stderr}, qr/--jail is only for freebsd/, '--jail on Linux' );
{
	local $Monitoring::Sneck::Checks::base::OS = 'freebsd';
	local $Monitoring::Sneck::Checks::packages::PKG
		= $write->( 'pkg', '#!' . $^X . "\nprint qq{curl\\nsudo\\n} . ( \$ARGV[0] eq '-j' ? qq{nginx\\n} : '' );\n" );
	chmod( 0755, $dir . '/pkg' );
	is( $run->( 'packages', '-i', 'sudo', '-a', 'nginx' )->{code}, 0, 'FreeBSD' );
	is(
		$run->( 'packages', '-a', 'nginx', '-j', 'www' )->{stdout},
		"PACKAGES CRITICAL - nginx is installed in jail www\n",
		'FreeBSD jail'
	);
}
is( $run->('packages')->{code}, 3, 'nothing to check' );

# accounts
local $Monitoring::Sneck::Checks::accounts::PASSWD = $write->( 'passwd', <<'END' );
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
alice:x:1001:1001:Alice:/home/alice:/bin/bash
END
local $Monitoring::Sneck::Checks::accounts::SHADOW
	= $write->( 'shadow', "root:\$y\$j9T\$abc:20000:0:99999:7:::\ndaemon:*:20000::::::\nalice:!:20000::::::\n" );
local $Monitoring::Sneck::Checks::accounts::SHELLS
	= $write->( 'shells', "# shells\n# /bin/zsh is not installed\n  /bin/sh # the default\n/bin/bash\n" );
$return = $run->( 'accounts', '-s', '-p', 'alice', '-a', 'guest' );
is( $return->{code},   0,                            'fine' );
is( $return->{stdout}, "ACCOUNTS OK - 5 accounts\n", 'output' );
is_deeply( [ Monitoring::Sneck::Checks::accounts->new->shells ], [ '/bin/sh', '/bin/bash' ], 'shells as getusershell' );

# backup has a shell only named in a comment, and nopw a empty field in passwd that shadow does not override
$write->( 'passwd', <<'END' );
root:x:0:0:root:/root:/bin/bash
toor:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
backup:x:1:34:backup:/var/backups:/bin/zsh
guest:x:1002:1002::/home/guest:/bin/bash
guest:x:1003:1003::/home/guest:/bin/bash
nopw::1004:1004::/home/nopw:/usr/sbin/nologin
END
$write->( 'shadow', "root:\$y\$j9T\$abc:20000::::::\ntoor:::::::\nguest:::::::\nnopw:\$y\$j9T\$abc:20000::::::\n" );
is(
	$run->( 'accounts', '-s', '-p', 'alice', '-a', 'guest' )->{stdout},
	"ACCOUNTS CRITICAL - 7 accounts, UID 0 for toor, more than one account with the name guest, more than one account with the uid 1, no password for guest, nopw, toor, system accounts with a login shell, daemon, there but should not be, guest, missing alice\n",
	'every problem'
);
{
	local $Monitoring::Sneck::Checks::base::OS = 'freebsd';
	like(
		$run->( 'accounts', '-n' )->{stdout},
		qr/\AACCOUNTS CRITICAL - 7 accounts, more than one account/,
		'toor allowed on FreeBSD'
	);
	local $Monitoring::Sneck::Checks::accounts::MASTER_PASSWD = $dir . '/nope';
	like(
		$run->('accounts')->{stdout},
		qr/\AACCOUNTS CRITICAL - .*, can not read the passwords, \S+nope\n\z/,
		'unreadable passwords noted'
	);
	is( $run->('accounts')->{code}, 2, 'CRITICAL is worse than the UNKNOWN for it' );
}
$write->( 'passwd', "root:x:0:0:root:/root:/bin/bash\n" );
{
	local $Monitoring::Sneck::Checks::accounts::SHADOW = $dir . '/nope';
	is( $run->('accounts')->{code},         3, 'only unreadable passwords is UNKNOWN' );
	is( $run->( 'accounts', '-n' )->{code}, 0, '--no-passwords' );
}

done_testing();
