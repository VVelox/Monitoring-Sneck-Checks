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
use Monitoring::Sneck::Checks::reboot_needed;

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
$write->( 'boot/vmlinuz-6.1.0-28-amd64',        '' );
$write->( 'boot/vmlinuz-6.12.48+deb13-amd64',   '' );
$write->( 'modules/6.1.0-38-amd64/modules.dep', '' );
$write->(
	'proc/version',
	'Linux version 6.12.48+deb13-amd64 (debian-kernel@lists.debian.org) (x86_64-linux-gnu-gcc-14 (Debian 14.2.0-19) 14.2.0) #1 SMP PREEMPT_DYNAMIC Debian 6.12.48-1 (2025-09-20)'
		. "\n"
);
my $status = $write->( 'status', <<'END' );
Package: linux-image-6.12.48+deb13-amd64
Status: install ok installed
Version: 6.12.48-1

Package: linux-image-6.1.0-28-amd64
Status: deinstall ok config-files
Version: 6.1.123-1
END
local $Monitoring::Sneck::Checks::base::OS                       = 'linux';
local $Monitoring::Sneck::Checks::base::PROC                     = $dir . '/proc';
local $Monitoring::Sneck::Checks::reboot_needed::BOOT            = $dir . '/boot';
local $Monitoring::Sneck::Checks::reboot_needed::MODULES         = $dir . '/modules';
local $Monitoring::Sneck::Checks::reboot_needed::DPKG_STATUS     = $status;
local $Monitoring::Sneck::Checks::reboot_needed::REBOOT_REQUIRED = $dir . '/reboot-required';
local $Monitoring::Sneck::Checks::reboot_needed::RELEASE         = '6.12.48+deb13-amd64';
my $run = sub { return Monitoring::Sneck::Checks->run( check => 'reboot_needed', args => [@_] ) };

my $return = $run->();
is( $return->{code},   0, 'nothing waiting, a old modules dir ignored' );
is( $return->{stdout}, "REBOOT_NEEDED OK - running 6.12.48+deb13-amd64, nothing is waiting on a reboot\n", 'output' );

$write->( 'boot/vmlinuz-6.12.57+deb13-amd64', '' );
is(
	$run->()->{stdout},
	"REBOOT_NEEDED WARNING - kernel 6.12.57+deb13-amd64 is installed, but 6.12.48+deb13-amd64 is running\n",
	'newer kernel'
);
unlink( $dir . '/boot/vmlinuz-6.12.57+deb13-amd64' );
$write->( 'modules/6.12.57+deb13-amd64/vmlinuz', '' );
is( $run->('-c')->{code}, 2, 'newer kernel in /lib/modules, CRITICAL with -c' );
unlink( $dir . '/modules/6.12.57+deb13-amd64/vmlinuz' );

$write->( 'status', <<'END' );
Package: linux-image-6.12.48+deb13-amd64
Status: install ok installed
Version: 6.12.48-2
END
is(
	$run->()->{stdout},
	"REBOOT_NEEDED WARNING - linux-image-6.12.48+deb13-amd64 6.12.48-2 is installed, but 6.12.48-1 is running\n",
	'same release, newer package'
);
$write->( 'status', "Package: linux-image-6.12.48+deb13-amd64\nStatus: install ok installed\nVersion: 6.12.48-1\n" );

$write->( 'reboot-required',      "*** System restart required ***\n" );
$write->( 'reboot-required.pkgs', "libc6\nlinux-base\nlibc6\n" );
is(
	$run->()->{stdout},
	qq{REBOOT_NEEDED WARNING - $dir/reboot-required is there, "System restart required"\nfor libc6, linux-base\n},
	'reboot-required'
);
unlink( $dir . '/reboot-required', $dir . '/reboot-required.pkgs' );

# replaced libraries, through a fake /proc
$write->(
	'proc/100/maps',
	"7f00-7f01 r-xp 00000000 08:01 1234 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n7f02-7f03 r-xp 00000000 08:01 1235 /usr/lib/x86_64-linux-gnu/libc.so.6\n"
);
$write->( 'proc/100/comm', "nginx\n" );
$write->(
	'proc/200/maps',
	"7f00-7f01 r-xp 00000000 08:01 1236 /usr/lib/x86_64-linux-gnu/libc.so.6\n00400000-00401000 rw-s 00000000 00:01 99 /dev/shm/x (deleted)\n"
);
$write->( 'proc/200/comm', "bash\n" );
$write->(
	'proc/300/maps',
	"7f00-7f01 r-xp 00000000 08:01 1234 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n7f04-7f05 r-xp 00000000 08:01 1237 /usr/lib/libcrypto.so.3 (deleted)\n"
);
$write->( 'proc/300/comm', "sshd\n" );
is( $run->()->{code}, 0, 'replaced libraries only with -l' );
is(
	$run->('-l')->{stdout},
	"REBOOT_NEEDED WARNING - 2 processes using replaced libraries\nnginx[100] uses libssl.so.3\nsshd[300] uses libcrypto.so.3, libssl.so.3\n",
	'-l'
);
is( $run->( '-l', '-n', 1 )->{stdout},
	"REBOOT_NEEDED WARNING - 2 processes using replaced libraries\nnginx[100] uses libssl.so.3\nand 1 more\n",
	'-n' );

# FreeBSD
my $freebsd_version = sub {
	my ( $installed, $running ) = @_;
	$write->( 'freebsd-version', '#!' . $^X . "\nprint qq{$installed\\n$running\\n};\n" );
	chmod( 0755, $dir . '/freebsd-version' );
	return $dir . '/freebsd-version';
};
{
	local $Monitoring::Sneck::Checks::base::OS               = 'freebsd';
	local $Monitoring::Sneck::Checks::reboot_needed::RELEASE = '14.1-RELEASE-p5';
	local $Monitoring::Sneck::Checks::reboot_needed::FREEBSD_VERSION
		= $freebsd_version->( '14.1-RELEASE-p5', '14.1-RELEASE-p5' );
	is( $run->()->{code}, 0, 'FreeBSD running what is installed' );
	$Monitoring::Sneck::Checks::reboot_needed::FREEBSD_VERSION
		= $freebsd_version->( '14.1-RELEASE-p6', '14.1-RELEASE-p5' );
	is(
		$run->()->{stdout},
		"REBOOT_NEEDED WARNING - kernel 14.1-RELEASE-p6 is installed, but 14.1-RELEASE-p5 is running\n",
		'FreeBSD newer kernel'
	);
}
{
	local $Monitoring::Sneck::Checks::base::OS = 'solaris';
	like( $run->()->{stderr}, qr/not supported on solaris/, 'other OSes' );
}

# version ordering
my $cmp = \&Monitoring::Sneck::Checks::reboot_needed::_version_cmp;
is( $cmp->( '6.12.48+deb13-amd64', '6.1.0-38-amd64' ),  1, '6.12 after 6.1' );
is( $cmp->( '6.12.9-amd64',        '6.12.48-amd64' ),  -1, '9 before 48' );
is( $cmp->( '6.12.48-amd64',       '6.12.48-amd64' ),   0, 'same' );

done_testing();
