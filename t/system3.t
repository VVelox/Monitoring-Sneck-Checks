#!perl
use 5.014;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Monitoring::Sneck::Checks;
use Monitoring::Sneck::Checks::base;
use Monitoring::Sneck::Checks::containers;
use Monitoring::Sneck::Checks::jails;
use Monitoring::Sneck::Checks::swap;

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
my %sysctl;
{
	no warnings 'once';
	$INC{'BSD/Sysctl.pm'} = __FILE__;
	*BSD::Sysctl::sysctl = sub { return $sysctl{ $_[0] } };
}

# pressure
my $psi = sub {
	my ( $resource, $some, $full ) = @_;
	$write->(
		'proc/pressure/' . $resource,
		"some avg10=$some avg60=$some avg300=1.00 total=1000\nfull avg10=$full avg60=$full avg300=0.50 total=500\n"
	);
};
$psi->( 'cpu',    '5.00',  '0.00' );
$psi->( 'memory', '25.50', '10.00' );
$psi->( 'io',     '1.00',  '0.50' );
is(
	$run->('pressure')->{stdout},
	"PRESSURE WARNING - some stalled over 60 seconds, cpu 5.00%, memory 25.50%, io 1.00% | cpu_some=5.00%;20;50;0;100 memory_some=25.50%;20;50;0;100 io_some=1.00%;20;50;0;100\n",
	'some, avg60'
);
is(
	$run->( 'pressure', '-k', 'full', '-w', 5, '-c', 9 )->{stdout},
	"PRESSURE CRITICAL - full stalled over 60 seconds, memory 10.00%, io 0.50% | memory_full=10.00%;5;9;0;100 io_full=0.50%;5;9;0;100\n",
	'full leaves out cpu'
);
is(
	$run->( 'pressure', '-r', 'memory', '--memory-warning', 30, '-a', 300 )->{stdout},
	"PRESSURE OK - some stalled over 300 seconds, memory 1.00% | memory_some=1.00%;30;50;0;100\n",
	'one resource, its own range, avg300'
);
is( $run->( 'pressure', '-r', 'disk' )->{code}, 3, 'bad --resource' );
is( $run->( 'pressure', '-a', 5 )->{code},      3, 'bad --average' );
is(
	$run->( 'pressure', '-r', 'cpu', '-k', 'full' )->{stderr},
	"PRESSURE UNKNOWN - nothing to check, as full is left out for cpu\n",
	'full with only cpu is nothing to check'
);
is(
	$run->( 'pressure', '-r', 'cpu', '-r', 'io', '-k', 'full' )->{stdout},
	"PRESSURE OK - full stalled over 60 seconds, io 0.50% | io_full=0.50%;20;50;0;100\n",
	'full with cpu and io checks io'
);
unlink( $dir . '/proc/pressure/io' );
like( $run->('pressure')->{stderr}, qr/no pressure stall information/, 'no PSI' );

# neighbors
my $neighbors = sub {
	my ( $arp_entries, $arp_fulls ) = @_;
	my $header
		= "entries  allocs   destroys hash_grows lookups  hits     res_failed rcv_probes_mcast rcv_probes_ucast periodic_gc_runs forced_gc_runs unresolved_discards table_fulls\n";
	my $row = sub {
		sprintf(
			'%08x 000000a9 0000005f 00000000 00643730 00109f4c 00000056 00000000 00000000 00083eb0 00000000 00000000 %08x',
			@_ ) . "\n";
	};
	$write->( 'proc/net/stat/arp_cache',   $header . $row->( $arp_entries, $arp_fulls ) . $row->( $arp_entries, 0 ) );
	$write->( 'proc/net/stat/ndisc_cache', $header . $row->( 10,           0 ) );
}; ## end $neighbors = sub
$neighbors->( 900, 0 );
$write->( 'proc/sys/net/ipv4/neigh/default/gc_thresh3', "1024\n" );
$write->( 'proc/sys/net/ipv6/neigh/default/gc_thresh3', "1024\n" );
is(
	$run->('neighbors')->{stdout},
	"NEIGHBORS WARNING - arp 900 of 1024, ndp 10 of 1024 | arp=87.9%;80;90;0;100 ndp=1.0%;80;90;0;100\n",
	'how full'
);
$neighbors->( 100, 3 );
is(
	$run->('neighbors')->{stdout},
	"NEIGHBORS CRITICAL - arp 100 of 1024, full 3 times since the last check, ndp 10 of 1024 | arp=9.8%;80;90;0;100 ndp=1.0%;80;90;0;100\n",
	'table fulls since the last check'
);
is( $run->('neighbors')->{code}, 0, 'no new fulls' );

# swap rates
$write->( 'proc/meminfo', "MemTotal: 8388608 kB\nSwapTotal: 2097152 kB\nSwapFree: 2097152 kB\n" );
$write->( 'proc/vmstat',  "pswpin 100\npswpout 200\n" );
like(
	$run->( 'swap', '-W', 10 )->{stdout},
	qr/\ASWAP OK - 0.0% used, 0 of 2048 MiB, no swap rate yet \|/,
	'no rate the first time'
);
$write->( 'proc/vmstat', "pswpin 1000100\npswpout 2000200\n" );
like( $run->( 'swap', '-W', 10 )->{stdout},
	qr/\ASWAP WARNING - .*, swapping [0-9.]+ pages\/s in and [0-9.]+ out \| swap_in=/, 'swapping' );
like( $run->('swap')->{stdout}, qr/\ASWAP OK - 0.0% used, 0 of 2048 MiB \|/, 'no rate without the options' );
{
	local $Monitoring::Sneck::Checks::base::OS       = 'freebsd';
	local $Monitoring::Sneck::Checks::swap::SWAPINFO = $stand_in->(
		'swapinfo', "print qq{Device 1K-blocks Used Avail Capacity\\n/dev/ada0p3 2097152 0 2097152 0%\\n};\n"
	);
	%sysctl = ( 'vm.stats.vm.v_swappgsin' => 5, 'vm.stats.vm.v_swappgsout' => 7 );
	like( $run->( 'swap', '-C', 1 )->{stdout}, qr/no swap rate yet/, 'FreeBSD, a reboot starts over' );
}

# procs open files, through a fake /proc for a child
my $marker = 'sneck_checks_fds_' . $$;
my $pid    = fork();
die($!)                                if !defined($pid);
exec( $^X, '-e', 'sleep 30', $marker ) if !$pid;
END { kill( 'TERM', $pid ) if $pid }
select( undef, undef, undef, 0.3 );
$write->( 'proc/' . $pid . '/fd/' . $_, '' ) foreach 0 .. 8;
$write->(
	'proc/' . $pid . '/limits',
	"Limit                     Soft Limit           Hard Limit           Units\nMax open files            10                   4096                 files\n"
);
is(
	$run->( 'procs', '-r', $marker, '--fd-warning', 80, '--fd-critical', 95 )->{stdout},
	"PROCS WARNING - 1 process matching /$marker/, most of its open file limit 90.0% by $pid, 9 of 10 | procs=1;;1:;0 fd_max=90.0%;80;95;0\n",
	'--fd-warning'
);
unlink( $dir . '/proc/' . $pid . '/limits' );
like( $run->( 'procs', '-r', $marker, '--fd-warning', 80 )->{stdout},
	qr/, 1 could not be read for open files \|/, 'unreadable' );
{
	local $Monitoring::Sneck::Checks::base::OS = 'freebsd';
	like( $run->( 'procs', '--fd-warning', 80 )->{stderr}, qr/only for linux/, 'not on FreeBSD' );
}

# containers
local $Monitoring::Sneck::Checks::containers::RUNTIMES{docker} = $stand_in->( 'docker', <<'END' );
print "web\trunning\tUp 3 hours (healthy)\n";
print "db\trunning\tUp 3 hours (unhealthy)\n";
print "worker\trestarting\tRestarting (1) 5 seconds ago\n";
print "old\texited\tExited (0) 2 days ago\n";
print "buildkit\trunning\tUp 1 hour (unhealthy)\n";
END
local $Monitoring::Sneck::Checks::containers::RUNTIMES{podman} = $dir . '/nope';
is(
	$run->( 'containers', '-n', 'web', '-n', 'old', '-n', 'cache', '-x', '^build' )->{stdout},
	"CONTAINERS CRITICAL - 3 of 5 containers running, old is exited, cache is not there, db is unhealthy, worker is restarting | running=3;;;0\n",
	'containers'
);
is( $run->( 'containers', '-n', 'web', '-x', '^(build|db|worker)' )->{code}, 0, 'OK' );
is(
	$run->( 'containers', '-r', 'podman' )->{stdout},
	"CONTAINERS UNKNOWN - podman is not there\n",
	'runtime not there'
);
{
	local $Monitoring::Sneck::Checks::containers::RUNTIMES{docker} = $stand_in->(
		'docker_denied',
		"print STDERR qq{permission denied while trying to connect to the Docker daemon socket\\n}; exit 1;\n"
	);
	like(
		$run->('containers')->{stdout},
		qr/\ACONTAINERS UNKNOWN - docker ps exited 1, "permission denied/,
		'no access'
	);
}

# jails
{
	local $Monitoring::Sneck::Checks::base::OS   = 'freebsd';
	local $Monitoring::Sneck::Checks::jails::JLS = $stand_in->( 'jls', "print qq{name=www\\nname=db\\n};\n" );
	local $Monitoring::Sneck::Checks::jails::VM  = $stand_in->(
		'vm',
		"print qq{NAME     DATASTORE  LOADER  CPU  MEMORY  VNC  AUTO     STATE\\nrouter   default    bhyveload  2  2G  -  Yes [1]  Running (1234)\\nnas      default    uefi    4    8G      -    No       Stopped\\n};\n"
	);
	local $Monitoring::Sneck::Checks::jails::JAIL_CONF = $write->( 'jail.conf', <<'END' );
exec.start = "/bin/sh /etc/rc";
path = "/jails/$name";
# old { not a jail }
www {
	host.hostname = "www.example.org";
	exec.poststart = "logger {started}";
}
db { ip4.addr = 192.0.2.20; }
/* gone { } */
END
	local $Monitoring::Sneck::Checks::jails::JAIL_CONF_D = $dir . '/jail.conf.d';
	$write->( 'jail.conf.d/mail.conf', "mail {\n\tpath = /jails/mail;\n}\n" );
	is_deeply(
		[ Monitoring::Sneck::Checks::jails->new( args => ['-a'] )->configured ],
		[ 'db', 'mail', 'www' ],
		'jail.conf parsed'
	);
	is( $run->( 'jails', '-j', 'www', '-j', 'db' )->{stdout}, "JAILS OK - 2 jails running\n", 'jails running' );
	is(
		$run->( 'jails', '-a' )->{stdout},
		"JAILS CRITICAL - 2 jails running, jail mail is not running\n",
		'--all-configured'
	);
	is( $run->( 'jails', '-a', '-x', 'mail' )->{code}, 0, '--exclude' );
	is( $run->( 'jails', '-v', 'router', '-v', 'nas', '-v', 'gone' )->{stdout},
		"JAILS CRITICAL - 1 VMs running, VM nas is stopped, VM gone is not there\n", 'VMs' );
}
like( $run->( 'jails', '-j', 'www' )->{stderr}, qr/not supported on linux/, 'Linux' );
is( $run->('jails')->{code}, 3, 'nothing to check' );

done_testing();
