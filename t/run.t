#!perl
use 5.014;
use strict;
use warnings;
use FindBin;
use lib $FindBin::Bin . '/lib';
use Test::More;
use Monitoring::Sneck::Checks;

my $run = sub { return Monitoring::Sneck::Checks->run(@_) };

# not loaded, -1
foreach my $bad (
	[ 'base',          qr/base is what checks are built on/ ],
	[ 'no_such_check', qr/failed to load Monitoring::Sneck::Checks::no_such_check/ ],
	[ 'broken',        qr/broken on purpose/ ],
	[ 'not_a_check',   qr/is not a check/ ],
	[ '../../etc',     qr/is not valid/ ],
	[ 'Http',          qr/is not valid/ ],
	[ 'http::foo',     qr/is not valid/ ],
	[ undef,           qr/is not valid/ ]
	)
{
	my $return = $run->( check => $bad->[0] );
	is( $return->{code}, -1, 'check ' . ( $bad->[0] // 'undef' ) . ' is -1' );
	like( $return->{stderr}, $bad->[1], 'and why' );
	is( $return->{combined}, $return->{stderr}, 'combined is stderr' );
	is( $return->{stdout},   '',                'nothing on stdout' );
} ## end foreach my $bad ( [ 'base', qr/base is what checks are built on/...])
my $return = $run->( check => 'testing', args => q{--out 'unbalanced} );
is( $return->{code},   3,                                                 'unbalanced quotes in args are UNKNOWN' );
is( $return->{stderr}, "TESTING UNKNOWN - args have unbalanced quotes\n", 'and says so' );
is_deeply(
	$run->( check => 'testing', args => q{--out "it's \"here\"" --err 'a b'} ),
	{ code => 0, stdout => qq{it's "here"\n}, stderr => "a b\n", combined => qq{it's "here"\na b\n} },
	'quoted string args split by Getopt::Long'
);

# codes
$return = $run->( check => 'testing', args => [ '--code', 2, '--out', 'some output', '--err', 'an error' ] );
is_deeply(
	$return,
	{ code => 2, stdout => "some output\n", stderr => "an error\n", combined => "some output\nan error\n" },
	'code, stdout, stderr, and combined'
);
is( $run->( check => 'testing', args => '--code 1' )->{code}, 1, 'args as a string' );
foreach my $odd ( 4, -1, 'undef', 'yes' ) {
	$return = $run->( check => 'testing', args => [ '--code', $odd ] );
	is( $return->{code}, 3, 'returning ' . $odd . ' is UNKNOWN' );
	like( $return->{stderr}, qr/\ATESTING UNKNOWN - returned "\Q$odd\E", not 0, 1, 2, or 3/, 'and says so' );
}

# dying, bad args, and timing out are UNKNOWN
$return = $run->( check => 'testing', args => [ '--out', 'before', '--die', 'it broke' ] );
is( $return->{code},     3,                                      'dying is UNKNOWN' );
is( $return->{combined}, "before\nTESTING UNKNOWN - it broke\n", 'output before it died is kept' );
$return = $run->( check => 'testing', args => [ '--nope', 'extra', '-w', 'bad' ] );
is( $return->{code}, 3, 'bad args are UNKNOWN' );
is(
	$return->{stderr},
	'TESTING UNKNOWN - Unknown option: nope, unexpected arg "extra", --warning "bad" is not a valid range' . "\n",
	'every problem with them listed'
);
$return = $run->( check => 'testing', args => [ '--sleep', 3 ], timeout => 0.5 );
is( $return->{code}, 3, 'timing out is UNKNOWN' );
like( $return->{stderr}, qr/timed out after 0.5 seconds/, 'and says so' );
is( alarm(0), 0, 'no alarm left behind' );

# stray prints and warnings are caught
$return = $run->( check => 'testing', args => [ '--print', "printed\n", '--warn', 'warned' ] );
is( $return->{stdout},   "printed\n",         'printed goes to stdout' );
is( $return->{stderr},   "warned\n",          'warned goes to stderr' );
is( $return->{combined}, "printed\nwarned\n", 'and combined' );

# finish and perfdata through a check
$return = $run->( check => 'testing', args => [ '--value', 15, '-w', 10, '-c', 20 ] );
is( $return->{code},   1,                                                  'value over warning' );
is( $return->{stdout}, "TESTING WARNING - value is 15 | value=15;10;20\n", 'status line and perfdata' );

done_testing();
