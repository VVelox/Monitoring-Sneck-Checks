#!perl
use 5.014;
use strict;
use warnings;
use FindBin;
use Test::More;

my @perl   = ( $^X, '-I' . $FindBin::Bin . '/../lib', '-I' . $FindBin::Bin . '/lib' );
my $script = $FindBin::Bin . '/../src_bin/sneck_check';

my $output = `@perl $script testing --code 2 --out hello --err oops`;
is( $? >> 8, 2,               'exits with the code' );
is( $output, "hello\noops\n", 'prints combined' );
$output = `@perl $script -a testing --out hello --err oops`;
is( $output, "stdout:\nhello\nstderr:\noops\n", '-a prints them apart' );
`@perl $script base 2>&1`;
is( $? >> 8, 3, 'not loaded exits 3' );
`@perl $script 2>&1`;
is( $? >> 8, 3, 'no check exits 3' );

done_testing();
