#!perl
use 5.014;
use strict;
use warnings;
use FindBin;
use lib $FindBin::Bin . '/lib';
use Test::More;
use File::Temp qw(tempdir);
use FakeDNS;
use Monitoring::Sneck::Checks;

my $dir   = tempdir( CLEANUP => 1 );
my $write = sub {
	my ( $name, $content ) = @_;
	open( my $fh, '>', $dir . '/' . $name ) or die($!);
	print $fh $content;
	close($fh);
	return $dir . '/' . $name;
};
my $run = sub {
	my ( $check, @args ) = @_;
	return Monitoring::Sneck::Checks->run( check => $check, args => \@args );
};

# resolv
my $resolv = $write->(
	'resolv.conf',
	"# a comment\nsearch example.org .\nnameserver 192.0.2.53\nnameserver fe80::1%em0 ; local\noptions edns0\n"
);
my $return = $run->( 'resolv', '-f', $resolv );
is( $return->{code},   0,                                                                    'good resolv.conf' );
is( $return->{stdout}, 'RESOLV OK - ' . $resolv . ", nameservers 192.0.2.53, fe80::1%em0\n", 'output' );
$return
	= $run->( 'resolv', '-f', $write->( 'bad.conf', "nameserver bogus\nsearch bad_domain\nfrobnicate yes\ndomain\n" ) );
is( $return->{code}, 1, 'bad resolv.conf is WARNING' );
like(
	$return->{stdout},
	qr/nameservers none, line 1 nameserver "bogus" is not a IP, line 2 search "bad_domain" is not a domain, line 3 has unknown keyword "frobnicate", line 4 has nothing after domain, no nameservers, so the local host is used\n\z/,
	'every problem'
);
like(
	$run->( 'resolv', '-f', $write->( 'many.conf', join( '', map { 'nameserver 192.0.2.' . $_ . "\n" } 1 .. 4 ) ) )
		->{stdout},
	qr/4 nameservers, but only the first 3 are used/,
	'too many nameservers'
);
is( $run->( 'resolv', '-f', $dir . '/nope' )->{code}, 2, 'missing is CRITICAL' );

%FakeDNS::ANSWERS = ( 'www.example.org a' => { answer => ['www.example.org. 300 IN A 192.0.2.10'] } );
is( $run->( 'resolv', '-f', $resolv, '-q', 'www.example.org' )->{code}, 0, 'both answer' );
is_deeply(
	[ map { $_->[0][0] } @FakeDNS::ASKED[ -2, -1 ] ],
	[ '192.0.2.53', 'fe80::1' ],
	'each asked, without the scope'
);
is( $run->( 'resolv', '-f', $resolv, '-q', 'nope.example.org' )->{code}, 0, 'NXDOMAIN is a answer' );
{
	local $FakeDNS::ANSWERS{'down.example.org a'} = undef;
	$return = $run->( 'resolv', '-f', $resolv, '-q', 'down.example.org' );
	is( $return->{code}, 2, 'none answering is CRITICAL' );
	like( $return->{stdout}, qr/no nameserver answered for down.example.org/, 'and says so' );
}

# hosts
my $hosts = $write->( 'hosts',
	"127.0.0.1 localhost localhost.localdomain\n::1 localhost # v6\n192.0.2.20 db.example.org db\n" );
$return = $run->( 'hosts', '-f', $hosts, '-e', 'db=192.0.2.20', '-e', 'DB.example.org=192.0.2.20' );
is( $return->{code},   0,                                        'good hosts' );
is( $return->{stdout}, 'HOSTS OK - ' . $hosts . ", 3 entries\n", 'output' );
$return = $run->( 'hosts', '-f', $hosts, '-e', 'db=192.0.2.21', '-e', 'web=192.0.2.30' );
is( $return->{code}, 2, 'expected mapping wrong is CRITICAL' );
like( $return->{stdout}, qr/, db is 192.0.2.20, not 192.0.2.21, web is not in it, not 192.0.2.30\n\z/, 'and says so' );
$return = $run->( 'hosts', '-f', $write->( 'bad_hosts', "localhost 127.0.0.1\n192.0.2.1\n192.0.2.2 bad_name\n" ) );
is( $return->{code}, 1, 'bad hosts is WARNING' );
like(
	$return->{stdout},
	qr/0 entries, line 1 "localhost" is not a IP, line 2 has no names, line 3 "bad_name" is not a hostname, localhost is not in it\n\z/,
	'every problem'
);
is( $run->( 'hosts', '-f', $write->( 'no_local', "192.0.2.20 db\n" ), '--no-localhost' )->{code}, 0, '--no-localhost' );
is( $run->( 'hosts', '-f', $dir . '/nope' )->{code}, 2, 'missing is CRITICAL' );
is( $run->( 'hosts', '-e', 'db' )->{code},           3, 'bad --expect' );

# file_age
my $file = $write->( 'age', 'x' x 100 );
utime( time - 300, time - 300, $file );
$return = $run->( 'file_age', '-f', $file );
is( $return->{code}, 1, 'over 240 seconds is WARNING' );
like( $return->{stdout},
	qr/\AFILE_AGE WARNING - \Q$file\E is 30\d seconds old and 100 bytes \| age=30\ds;240;600 size=100B;;;0\n\z/,
	'output' );
is( $run->( 'file_age', '-f', $file, '-w', 400, '-c', 500 )->{code},                0, 'OK' );
is( $run->( 'file_age', '-f', $file, '-c', 200 )->{code},                           2, 'CRITICAL' );
is( $run->( 'file_age', '-f', $file, '-w', 400, '-c', 500, '-W', '1024:' )->{code}, 1, 'too small' );
is( $run->( 'file_age', '-f', $file, '-w', 400, '-c', 500, '-C', '50' )->{code},    2, 'too big' );
is( $run->( 'file_age', '-f', $dir . '/nope' )->{code},                             2, 'missing is CRITICAL' );
is( $run->( 'file_age', '-f', $dir . '/nope', '-i' )->{code},                       0, 'missing is OK with -i' );
is( $run->( 'file_age', '-f', $file, '-W', 'big' )->{code},                         3, 'bad range' );

# file_age, the newest of a glob
my $older = $write->( 'db-2026-10-30.sql', 'x' x 10 );
my $newer = $write->( 'db-2026-10-31.sql', 'x' x 20 );
utime( time - 7200, time - 7200, $older );
utime( time - 100,  time - 100,  $newer );
like( $run->( 'file_age', '-n', $dir . '/db-*.sql' )->{stdout},
	qr/\AFILE_AGE OK - the newest of \S+db-\*.sql, \Q$newer\E is 10\d seconds old and 20 bytes \|/, '--newest' );
is(
	$run->( 'file_age', '-n', $dir . '/backup-*' )->{stdout},
	"FILE_AGE CRITICAL - nothing matches $dir/backup-*\n",
	'nothing matching'
);
is( $run->( 'file_age', '-n', $dir . '/backup-*', '-i' )->{code},    0, 'nothing matching with -i' );
is( $run->( 'file_age', '-n', $dir . '/db-*', '-f', $file )->{code}, 3, '--newest and --file' );
is( $run->('file_age')->{code},                                      3, 'neither' );

done_testing();
