#!perl
use 5.014;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
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

# file_mode, owned by whoever runs the tests
my $user  = getpwuid($<);
my $group = getgrgid( ( split( / /, $( ) )[0] );
my $file  = $write->( 'secret', 'x' );
chmod( 0600, $file );
my $return = $run->( 'file_mode', '-f', $file, '-m', '0600', '-o', $user );
is( $return->{code},   0,                                                                  'mode and owner' );
is( $return->{stdout}, 'FILE_MODE OK - ' . $file . ' 0600 ' . $user . ':' . $group . "\n", 'output' );
is( $run->( 'file_mode', '-f', $file, '-M', '0640', '-o', $<, '-g', ( stat($file) )[5] )->{code},
	0, '--max-mode allows less, IDs' );
chmod( 0644, $file );
$return = $run->( 'file_mode', '-f', $file, '-M', '0640', '-m', '0600' );
is( $return->{code}, 2, 'too open is CRITICAL' );
is(
	$return->{stdout},
	'FILE_MODE CRITICAL - '
		. $file
		. ' 0644 '
		. $user . ':'
		. $group
		. ", mode is not 0600, mode is more than 0640\n",
	'and says how'
);
like( $run->( 'file_mode', '-f', $file, '-o', 0 )->{stdout}, qr/, owner is not 0\n\z/, 'wrong owner' ) if $< != 0;
mkdir( $dir . '/sticky' );
chmod( 01777, $dir . '/sticky' );
is( $run->( 'file_mode', '-f', $dir . '/sticky', '-m', '1777' )->{code}, 0, 'sticky directory' );
like( $run->( 'file_mode', '-f', $dir . '/nope', '-m', '0600' )->{stdout},
	qr/\AFILE_MODE CRITICAL - \S+nope, No such file/, 'missing' );
is( $run->( 'file_mode', '-f', $dir . '/nope', '-m', '0600', '-i' )->{code}, 0, 'missing with -i' );

foreach my $bad ( [ '-f', $file ], [ '-f', $file, '-m', '644x' ], [ '-f', $file, '-o', 'no-such-user-here' ] ) {
	is( $run->( 'file_mode', @{$bad} )->{code}, 3, 'bad args, ' . join( ' ', @{$bad} ) );
}

# sshd_config
make_path( $dir . '/ssh/sshd_config.d' );
my $sshd = $write->( 'ssh/sshd_config', <<'END' );
# a comment
Include sshd_config.d/*.conf
PermitRootLogin yes
PasswordAuthentication   no
Ciphers  "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"
MaxAuthTries=4
Match User backup
    PasswordAuthentication yes
    X11Forwarding yes
END
$write->( 'ssh/sshd_config.d/10-hardening.conf', "permitrootlogin No\n" );
$return = $run->(
	'sshd_config',      '-f', $sshd, '-e', 'PermitRootLogin=no', '-e', 'passwordauthentication=no', '-e',
	'MaxAuthTries=3|4', '-e', 'Ciphers=chacha20-poly1305@openssh.com,aes256-gcm@openssh.com'
);
is( $return->{code}, 0, 'settings, an include winning, case, =, and quotes' );
is(
	$return->{stdout},
	"SSHD_CONFIG OK - PermitRootLogin no, passwordauthentication no, MaxAuthTries 4, Ciphers chacha20-poly1305\@openssh.com,aes256-gcm\@openssh.com\n",
	'output'
);
$return = $run->( 'sshd_config', '-f', $sshd, '-e', 'MaxAuthTries=3', '-e', 'X11Forwarding=no' );
is( $return->{code}, 2, 'wrong and not set are CRITICAL' );
is( $return->{stdout}, "SSHD_CONFIG CRITICAL - MaxAuthTries is 4, not 3, X11Forwarding is not set\n",
	'Match left out' );
is( $run->( 'sshd_config', '-f', $sshd, '-e', 'X11Forwarding=no', '-d', 'X11Forwarding=no' )->{stdout},
	"SSHD_CONFIG OK - X11Forwarding no by default\n", '--default' );
like(
	$run->( 'sshd_config', '-f', $sshd, '-e', 'X11Forwarding=no', '-d', 'X11Forwarding=yes' )->{stdout},
	qr/X11Forwarding is yes by default, not no/,
	'--default not allowed'
);
like( $run->( 'sshd_config', '-f', $dir . '/nope', '-e', 'A=b' )->{stdout},
	qr/\ASSHD_CONFIG CRITICAL - can not read/, 'missing' );
$write->( 'ssh/loop', "Include loop\n" );
like(
	$run->( 'sshd_config', '-f', $dir . '/ssh/loop', '-e', 'A=b' )->{stdout},
	qr/Include goes over 16 deep/,
	'Include loop'
);
is( $run->( 'sshd_config', '-f', $sshd )->{code}, 3, 'no --expect' );
is( $run->( 'sshd_config', '-f', $sshd, '-e', 'PermitRootLogin' )->{code}, 3, 'bad --expect' );

done_testing();
