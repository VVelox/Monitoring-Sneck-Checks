#!perl
use 5.014;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Monitoring::Sneck::Checks;
use Monitoring::Sneck::Checks::base;

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

# pid_file, with this test as the process
require Proc::ProcessTable;
my ($self_process) = grep { $_->pid == $$ } @{ Proc::ProcessTable->new->table };
my $name           = $self_process->fname;
my $pid_file       = $write->( 'test.pid', $$ . "\n" );
is( $run->( 'pid_file', '-f', $pid_file )->{stdout}, "PID_FILE OK - $$ from $pid_file is running\n", 'running' );
is(
	$run->( 'pid_file', '-f', $pid_file, '-n', $name )->{stdout},
	"PID_FILE OK - $$ $name from $pid_file is running\n",
	'with its name'
);
is(
	$run->( 'pid_file', '-f', $pid_file, '-n', 'not-this' )->{stdout},
	"PID_FILE CRITICAL - $$ from $pid_file is $name, not not-this\n",
	'a other name'
);
my $dead = fork();
exit(0) if !$dead;
waitpid( $dead, 0 );
$write->( 'dead.pid', $dead );
is(
	$run->( 'pid_file', '-f', $dir . '/dead.pid' )->{stdout},
	"PID_FILE CRITICAL - $dead from $dir/dead.pid is not running\n",
	'not running'
);
$write->( 'junk.pid', "junk\n" );
is(
	$run->( 'pid_file', '-f', $dir . '/junk.pid' )->{stdout},
	"PID_FILE CRITICAL - $dir/junk.pid does not have a PID\n",
	'not a PID'
);
like( $run->( 'pid_file', '-f', $dir . '/nope.pid' )->{stdout},
	qr/\APID_FILE CRITICAL - can not read \S+nope.pid/, 'missing' );

# uptime
$write->( 'proc/uptime', "1049040.55 4000000.00\n" );
is( $run->('uptime')->{stdout}, "UPTIME OK - up 12 days, 3:24 | uptime=1049040s;900:;;0\n", 'uptime' );
is( $run->( 'uptime', '-w', '900:864000' )->{code}, 1,                                      'up too long' );
$write->( 'proc/uptime', "300.00 1200.00\n" );
is( $run->('uptime')->{stdout}, "UPTIME WARNING - up 0:05 | uptime=300s;900:;;0\n", 'just rebooted' );
{
	local $Monitoring::Sneck::Checks::base::OS = 'freebsd';
	foreach my $boot (
		{ sec => time - 90060, usec => 0 },
		[ time - 90060, 0 ],
		'{ sec = ' . ( time - 90060 ) . ', usec = 0 } Sat Oct  1 00:00:00 2026',
		time - 90060
		)
	{
		$sysctl{'kern.boottime'} = $boot;
		like(
			$run->('uptime')->{stdout},
			qr/\AUPTIME OK - up 1 day, 1:01 \|/,
			'FreeBSD kern.boottime as ' . ( ref($boot) || 'text' )
		);
	} ## end foreach my $boot ( { sec => time - 90060, usec ...})
}

# file_handles
$write->( 'proc/sys/fs/file-nr', "8500\t0\t10000\n" );
is( $run->('file_handles')->{stdout},
	"FILE_HANDLES WARNING - 85.0% used, 8500 of 10000 open | used=85.0%;80;90;0;100 open=8500;;;0;10000\n",
	'Linux' );
{
	local $Monitoring::Sneck::Checks::base::OS = 'freebsd';
	%sysctl = ( 'kern.openfiles' => 950, 'kern.maxfiles' => 1000 );
	is( $run->('file_handles')->{code}, 2, 'FreeBSD' );
}
{
	local $Monitoring::Sneck::Checks::base::OS = 'solaris';
	like( $run->('file_handles')->{stderr}, qr/not supported on solaris/, 'other OSes' );
}

done_testing();
