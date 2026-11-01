#!perl
use 5.014;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Monitoring::Sneck::Checks;
use Monitoring::Sneck::Checks::base;
use Monitoring::Sneck::Checks::swraid;
use Monitoring::Sneck::Checks::conntrack;
use Monitoring::Sneck::Checks::systemd_failed;
use Monitoring::Sneck::Checks::service;

my $dir   = tempdir( CLEANUP => 1 );
my $write = sub {
	my ( $name, $content ) = @_;
	my $path = $dir . '/' . $name;
	make_path( $path =~ s{/[^/]+\z}{}r );
	open( my $fh, '>', $path ) or die($!);
	print $fh $content;
	close($fh);
	return $path;
};
my $stand_in = sub {
	my ( $name, $code ) = @_;
	my $path = $write->( $name, '#!' . $^X . "\n" . $code );
	chmod( 0755, $path );
	return $path;
};
local $Monitoring::Sneck::Checks::base::OS        = 'linux';
local $Monitoring::Sneck::Checks::base::PROC      = $dir . '/proc';
local $Monitoring::Sneck::Checks::base::STATE_DIR = $dir . '/state';
my $run = sub {
	my ( $check, @args ) = @_;
	return Monitoring::Sneck::Checks->run( check => $check, args => \@args );
};

# swraid
my $mdstat = sub {
	$write->(
		'proc/mdstat',
		"Personalities : [raid1] [raid6] [raid5] [raid0]\n" . join( "\n", @_ ) . "\nunused devices: <none>\n"
	);
};
$mdstat->(
	"md0 : active raid1 sdb1[1] sda1[0]\n      1048512 blocks super 1.2 [2/2] [UU]\n",
	"md1 : active raid0 sdc1[1] sdd1[0]\n      2097024 blocks super 1.2 512k chunks\n",
	"md2 : active raid6 sde1[3] sdf1[2] sdg1[1] sdh1[0]\n      4190208 blocks super 1.2 level 6, 512k chunk, algorithm 2 [4/4] [UUUU]\n      [==>..................]  check = 12.5% (262144/2095104) finish=1.2min speed=20000K/sec\n",
);
is(
	$run->('swraid')->{stdout},
	"SWRAID OK - md0 raid1 ok, md1 raid0 ok, md2 raid6 ok, check 12.5%\n",
	'all fine, a check running'
);
$mdstat->(
	"md0 : active raid1 sdb1[1](F) sda1[0]\n      1048512 blocks super 1.2 [2/1] [U_]\n",
	"md1 : active (auto-read-only) raid1 sdd1[2] sdc1[0]\n      1048512 blocks super 1.2 [2/1] [U_]\n      [=>...................]  recovery =  8.5% (89600/1048512) finish=0.5min speed=29866K/sec\n",
	"md2 : active raid5 sdf1[1] sde1[0] sdg1[2]\n      2095104 blocks super 1.2 level 5, 512k chunk, algorithm 2 [3/3] [UUU]\n      [===>.................]  resync = 17.3% (181248/1047552) finish=0.4min speed=36249K/sec\n",
	"md3 : inactive sdh1[0](S)\n      1048576 blocks super 1.2\n",
);
is(
	$run->( 'swraid', '-a', 'md9' )->{stdout},
	"SWRAID CRITICAL - md9 is not there, md0 raid1 degraded, 1 of 2 working, failed sdb1, md1 raid1 degraded, 1 of 2 working, recovery 8.5%, md2 raid5 resync 17.3%, md3 is inactive\n",
	'degraded, failed, rebuilding, resyncing, inactive, missing'
);
$mdstat->(
	"md2 : active raid5 sdf1[1] sde1[0] sdg1[2]\n      2095104 blocks [3/3] [UUU]\n      [===>.................]  resync = 17.3% (181248/1047552)\n"
);
is( $run->('swraid')->{code}, 1, 'resyncing alone is WARNING' );
unlink( $dir . '/proc/mdstat' );
is( $run->('swraid')->{stdout}, "SWRAID OK - no software RAID arrays\n", 'no md at all' );
{
	local $Monitoring::Sneck::Checks::base::OS        = 'freebsd';
	local $Monitoring::Sneck::Checks::swraid::GMIRROR = $stand_in->(
		'gmirror',
		"print qq{mirror/gm0  COMPLETE  ada0 (ACTIVE)\\nmirror/gm0  COMPLETE  ada1 (ACTIVE)\\nmirror/gm1  DEGRADED  ada2 (ACTIVE)\\nmirror/gm1  DEGRADED  ada3 (SYNCHRONIZING, 45%)\\nmirror/gm2  DEGRADED  ada4 (ACTIVE)\\n};\n"
	);
	local $Monitoring::Sneck::Checks::swraid::GRAID
		= $stand_in->( 'graid', "print STDERR qq{graid: Class 'RAID' not found.\\n}; exit 1;\n" );
	is(
		$run->('swraid')->{stdout},
		"SWRAID CRITICAL - mirror/gm0 complete, mirror/gm1 degraded, ada3 synchronizing, 45%, mirror/gm2 degraded\n",
		'gmirror, graid not loaded'
	);
	$Monitoring::Sneck::Checks::swraid::GMIRROR = $dir . '/nope';
	$Monitoring::Sneck::Checks::swraid::GRAID   = $stand_in->(
		'graid_ok',
		"print qq{raid/r0  OPTIMAL  ada0 (ACTIVE (ACTIVE))\\nraid/r0  OPTIMAL  ada1 (ACTIVE (ACTIVE))\\n};\n"
	);
	is( $run->( 'swraid', '-a', 'raid/r0' )->{stdout}, "SWRAID OK - raid/r0 optimal\n", 'graid, gmirror not there' );
}

# conntrack
is( $run->('conntrack')->{stdout}, "CONNTRACK OK - conntrack is not loaded\n", 'not loaded' );
$write->( 'proc/sys/net/netfilter/nf_conntrack_count', "55000\n" );
$write->( 'proc/sys/net/netfilter/nf_conntrack_max',   "65536\n" );
is( $run->('conntrack')->{stdout},
	"CONNTRACK WARNING - conntrack 83.9% used, 55000 of 65536 | used=83.9%;80;90;0;100 entries=55000;;;0;65536\n",
	'Linux' );
{
	local $Monitoring::Sneck::Checks::base::OS         = 'freebsd';
	local $Monitoring::Sneck::Checks::conntrack::PFCTL = $stand_in->( 'pfctl', <<'END' );
if ( $ARGV[0] eq '-si' ) { print "Status: Enabled for 10 days 01:02:03           Debug: Urgent\n\nState Table                          Total             Rate\n  current entries                    95000\n  searches                         1234567            1.0/s\n"; exit 0 }
print "states        hard limit   100000\nsrc-nodes     hard limit    10000\n";
END
	is( $run->('conntrack')->{code}, 2, 'FreeBSD pf states' );
	like(
		$run->('conntrack')->{stdout},
		qr/\ACONNTRACK CRITICAL - pf states 95.0% used, 95000 of 100000/,
		'FreeBSD message'
	);
	$Monitoring::Sneck::Checks::conntrack::PFCTL
		= $stand_in->( 'pfctl_off', "print qq{Status: Disabled for 0 days 00:00:00\\n};\n" );
	is( $run->('conntrack')->{stdout}, "CONNTRACK OK - pf is not enabled\n", 'FreeBSD pf off' );
}

# oom
$write->( 'proc/vmstat', "nr_free_pages 1000\noom_kill 3\n" );
is( $run->('oom')->{stdout}, "OOM OK - first check, 3 OOM kills since boot | kills=0;0;;0\n", 'first check' );
is( $run->('oom')->{stdout}, "OOM OK - 0 OOM kills since the last check, 3 since boot | kills=0;0;;0\n", 'none since' );
$write->( 'proc/vmstat', "oom_kill 5\n" );
is( $run->( 'oom', '-H', 600 )->{stdout},
	"OOM WARNING - 2 OOM kills since the last check, 5 since boot | kills=2;0;;0\n", 'kills' );
like( $run->( 'oom', '-H', 600 )->{stdout},
	qr/\AOOM WARNING - 2 OOM kills since the last check, held from \d+ seconds ago, 5 since boot \|/, 'held' );
is( $run->('oom')->{code}, 0, 'not held without --hold' );
$write->( 'proc/vmstat', "oom_kill 1\n" );
like( $run->('oom')->{stdout}, qr/\AOOM OK - first check/, 'a reboot starts over' );
$write->( 'proc/vmstat', "nr_free_pages 1000\n" );
like( $run->('oom')->{stderr}, qr/does not count OOM kills/, 'old kernel' );

# systemd_failed
local $Monitoring::Sneck::Checks::systemd_failed::SYSTEMCTL = $stand_in->( 'systemctl_failed', <<'END' );
print "systemd-journal-flush.service loaded failed failed Flush Journal\n";
print "nginx.service                 loaded failed failed A high performance web server\n";
END
is(
	$run->('systemd_failed')->{stdout},
	"SYSTEMD_FAILED CRITICAL - 2 failed units, systemd-journal-flush.service, nginx.service | failed=2;;0;0\n",
	'failed units'
);
is( $run->( 'systemd_failed', '-x', 'flush', '-x', '^nginx' )->{stdout},
	"SYSTEMD_FAILED OK - 0 failed units | failed=0;;0;0\n", '--exclude' );
{
	local $Monitoring::Sneck::Checks::systemd_failed::SYSTEMCTL
		= $stand_in->( 'systemctl_down', "print qq{System has not been booted with systemd\\n}; exit 1;\n" );
	is(
		$run->('systemd_failed')->{stdout},
		qq{SYSTEMD_FAILED UNKNOWN - systemctl --failed exited 1, "System has not been booted with systemd"\n},
		'no systemd'
	);
}

# service
local $Monitoring::Sneck::Checks::service::SYSTEMCTL = $stand_in->( 'systemctl', <<'END' );
my ( $what, @rest ) = @ARGV;
my %active  = ( nginx => 'active', 'php8.4-fpm' => 'failed', web => 'inactive' );
my %enabled = ( nginx => 1 );
if ( $what eq 'is-active' ) { print( ( $active{ $rest[0] } // 'inactive' ) . "\n" ); exit( ( $active{ $rest[0] } // '' ) eq 'active' ? 0 : 3 ) }
if ( $what eq 'is-enabled' ) { exit( $enabled{ $rest[0] } ? 0 : 1 ) }
if ( $what eq 'show' ) { print( ( exists( $active{ $rest[-1] } ) ? 'loaded' : 'not-found' ) . "\n" ); exit 0 }
END
is( $run->( 'service', '-s', 'nginx', '-e' )->{stdout}, "SERVICE OK - nginx active\n", 'running and enabled' );
is(
	$run->( 'service', '-s', 'nginx', '-s', 'php8.4-fpm', '-s', 'web', '-s', 'nope' )->{stdout},
	"SERVICE CRITICAL - php8.4-fpm is failed, web is inactive, nope is not there\n",
	'not running'
);
{
	local $Monitoring::Sneck::Checks::service::SYSTEMCTL
		= $stand_in->( 'systemctl2', "exit( \$ARGV[0] eq 'is-active' ? 0 : 1 );\n" );
	is(
		$run->( 'service', '-s', 'cron', '-e' )->{stdout},
		"SERVICE CRITICAL - cron is running but not enabled\n",
		'not enabled'
	);
}
{
	local $Monitoring::Sneck::Checks::base::OS         = 'freebsd';
	local $Monitoring::Sneck::Checks::service::SERVICE = $stand_in->( 'service', <<'END' );
my @args = @ARGV;
my $jail = $args[0] eq '-j' ? splice( @args, 0, 2 ) && 1 : 0;
my ( $name, $what ) = @args;
if ( $name eq 'nope' ) { print STDERR "nope does not exist in /etc/rc.d or the local startup directories\n"; exit 1 }
if ( $what eq 'status' ) { exit( $name eq 'sshd' || ( $jail && $name eq 'nginx' ) ? 0 : 1 ) }
exit( $name eq 'sshd' ? 0 : 1 );
END
	is( $run->( 'service', '-s', 'sshd', '-e' )->{stdout}, "SERVICE OK - sshd running\n", 'FreeBSD' );
	is(
		$run->( 'service', '-s', 'nginx', '-s', 'nope' )->{stdout},
		"SERVICE CRITICAL - nginx is not running, nope is not there\n",
		'FreeBSD not running'
	);
	is(
		$run->( 'service', '-s', 'nginx', '-j', 'www' )->{stdout},
		"SERVICE OK - nginx running in jail www\n",
		'FreeBSD jail'
	);
}
like( $run->( 'service', '-s', 'nginx', '-j', 'www' )->{stderr}, qr/--jail is only for freebsd/, '--jail on Linux' );

done_testing();
