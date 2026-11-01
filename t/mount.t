#!perl
use 5.014;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Monitoring::Sneck::Checks;
use Monitoring::Sneck::Checks::base;
use Monitoring::Sneck::Checks::mount;

my $dir   = tempdir( CLEANUP => 1 );
my $write = sub {
	my ( $name, $content ) = @_;
	open( my $fh, '>', $dir . '/' . $name ) or die($!);
	print $fh $content;
	close($fh);
	return $dir . '/' . $name;
};
mkdir( $dir . '/proc' );
local $Monitoring::Sneck::Checks::base::OS     = 'linux';
local $Monitoring::Sneck::Checks::base::PROC   = $dir . '/proc';
local $Monitoring::Sneck::Checks::mount::FSTAB = $write->( 'fstab', <<'END' );
# <file system> <mount point> <type> <options> <dump> <pass>
UUID=1234-abcd /               ext4    errors=remount-ro 0 1
UUID=5678      /boot/          ext4    defaults          0 2
/dev/sdb1      /srv/my\040data xfs     defaults,nofail   0 2
/dev/sr0       /media/cdrom    udf     user,noauto       0 0
backup:/export /backup         nfs     ro,x-systemd.automount 0 0
/dev/sda3      none            swap    sw                0 0
END
my $mounts = sub {
	$write->( 'proc/mounts', join( '', map { $_ . "\n" } @_ ) );
};
my $run = sub { return Monitoring::Sneck::Checks->run( check => 'mount', args => [@_] ) };

$mounts->(
	'/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0',
	'/dev/sda2 /boot ext4 rw,relatime 0 0',
	'/dev/sdb1 /srv/my\040data xfs rw,relatime 0 0',
	'proc /proc proc rw,nosuid 0 0'
);
my $return = $run->();
is( $return->{code},   0,                        'all mounted, lazy ones not needed' );
is( $return->{stdout}, "MOUNT OK - 3 mounted\n", 'output' );

$mounts->( '/dev/sda1 / ext4 ro,relatime 0 0', '/dev/sda2 /boot ext4 rw 0 0', 'backup:/export /backup nfs4 ro 0 0' );
is(
	$run->()->{stdout},
	"MOUNT CRITICAL - 3 mounted, / is read only, /srv/my data is not mounted\n",
	'read only and not mounted, ro in fstab is fine'
);
is( $run->( '-i', '/srv/my data', '-i', '/' )->{stdout}, "MOUNT OK - 2 mounted\n", '--ignore' );
like( $run->( '-p', '/data/', '-i', '/srv/my data', '-i', '/' )->{stdout},
	qr/\AMOUNT CRITICAL - 2 mounted, \/data is not mounted\n\z/, '--path' );
is( $run->( '-n', '-p', '/boot' )->{stdout}, "MOUNT OK - 1 mounted\n", '--no-fstab' );
is( $run->('-n')->{code},                    3,                        '--no-fstab without --path' );
{
	local $Monitoring::Sneck::Checks::mount::FSTAB = $dir . '/nope';
	like( $run->()->{stdout}, qr/\AMOUNT UNKNOWN - can not read \S+nope/, 'fstab missing' );
}

# FreeBSD, through a stand in for mount -p
$write->(
	'mount',
	'#!'
		. $^X
		. "\nprint qq{/dev/ada0p2\\t/\\tufs\\trw\\t1\\t1\\nzroot/var\\t/var\\tzfs\\trw,noatime\\t0\\t0\\n};\n"
);
chmod( 0755, $dir . '/mount' );
{
	local $Monitoring::Sneck::Checks::base::OS     = 'freebsd';
	local $Monitoring::Sneck::Checks::mount::MOUNT = $dir . '/mount';
	local $Monitoring::Sneck::Checks::mount::FSTAB
		= $write->( 'fstab.freebsd', "/dev/ada0p2 / ufs rw 1 1\n/dev/ada0p3 none swap sw 0 0\n" );
	is( $run->( '-p', '/var' )->{stdout}, "MOUNT OK - 2 mounted\n", 'FreeBSD' );
}

done_testing();
