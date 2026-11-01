#!perl
use 5.014;
use strict;
use warnings;
use FindBin;
use lib $FindBin::Bin . '/lib';
use Test::More;
use File::Temp qw(tempdir);
use TestCerts;
use TestServer;
use IO::Socket::SSL;
use Monitoring::Sneck::Checks;
use Monitoring::Sneck::Checks::https_cert;

plan( skip_all => 'needs fork' ) if $^O eq 'MSWin32';

my $dir   = tempdir( CLEANUP => 1 );
my $paths = TestCerts::make( $dir, { name => 'www', days => 20, names => [ 'www.example.org', '127.0.0.1' ] } );
my @pids;
my $parent_pid = $$;
END { kill( 'TERM', @pids ) if @pids && $$ == $parent_pid }

my ( $plain_port, $plain_pid )
	= TestServer::start( greeting => "220 test ready\r\n", answers => { PING => "+PONG\r\n" } );
my ( $tls_port, $tls_pid ) = TestServer::start(
	greeting => "* OK ready\r\n",
	ssl      => { SSL_cert_file => $paths->{www} . '.pem', SSL_key_file => $paths->{www} . '.key' }
);
push( @pids, $plain_pid, $tls_pid );

# STARTTLS servers, each answering as the protocol does, then going TLS
my %server_ssl = ( SSL_server => 1, SSL_cert_file => $paths->{www} . '.pem', SSL_key_file => $paths->{www} . '.key' );
my $upgrade    = sub {
	my ($client) = @_;
	IO::Socket::SSL->start_SSL( $client, %server_ssl ) or return;
	sysread( $client, my $buffer, 10 );
};
my %starttls = (
	smtp => sub {
		my ($client) = @_;
		print $client "220-mail.example.org ESMTP\r\n220 ready\r\n";
		<$client> =~ /^EHLO / or return;
		print $client "250-mail.example.org\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 8BITMIME\r\n";
		<$client> eq "STARTTLS\r\n" or return;
		print $client "220 go ahead\r\n";
		$upgrade->($client);
	},
	smtp_no_tls => sub {
		my ($client) = @_;
		print $client "220 ready\r\n";
		<$client>;
		print $client "250-mail.example.org\r\n250 8BITMIME\r\n";
	},
	imap => sub {
		my ($client) = @_;
		print $client "* OK IMAP4rev1 ready\r\n";
		<$client> eq "a1 STARTTLS\r\n" or return;
		print $client "* note\r\na1 OK begin TLS\r\n";
		$upgrade->($client);
	},
	pop3 => sub {
		my ($client) = @_;
		print $client "+OK POP3 ready\r\n";
		<$client> eq "STLS\r\n" or return;
		print $client "+OK begin TLS\r\n";
		$upgrade->($client);
	},
	ftp => sub {
		my ($client) = @_;
		print $client "220 FTP ready\r\n";
		<$client> eq "AUTH TLS\r\n" or return;
		print $client "234 AUTH TLS ok\r\n";
		$upgrade->($client);
	},
	ldap => sub {
		my ($client) = @_;
		sysread( $client, my $request, 100 );
		return if $request ne $Monitoring::Sneck::Checks::https_cert::LDAP_STARTTLS;
		print $client pack( 'H*', '300c02010178070a010004000400' );
		$upgrade->($client);
	},
	ldap_refused => sub {
		my ($client) = @_;
		sysread( $client, my $request, 100 );
		print $client pack( 'H*', '300c02010178070a013404000400' );
	},
);
my %starttls_ports;
foreach my $protocol ( sort( keys(%starttls) ) ) {
	my ( $port, $pid ) = TestServer::start( handler => $starttls{$protocol} );
	$starttls_ports{$protocol} = $port;
	push( @pids, $pid );
}

# a port nothing is on
my $closed_port = do {
	my $socket = IO::Socket::IP->new( LocalHost => '127.0.0.1', LocalPort => 0, Listen => 1 );
	my $port   = $socket->sockport;
	close($socket);
	$port;
};
my $run = sub {
	my ( $check, @args ) = @_;
	return Monitoring::Sneck::Checks->run( check => $check, args => \@args, timeout => 5 );
};

# tcp
my $return = $run->( 'tcp', '-H', '127.0.0.1', '-p', $plain_port, '-e', '220 ', '-q', 'QUIT\r\n' );
is( $return->{code}, 0, 'banner' );
like( $return->{stdout}, qr/\ATCP OK - connected to 127.0.0.1:$plain_port in [0-9.]+ seconds \| time=[0-9.]+s;;;0\n\z/,
	'output' );
is(
	$run->( 'tcp', '-H', '127.0.0.1', '-p', $plain_port, '-s', 'PING\r\n', '-e', '+PONG', '-A', '-e', '220' )
		->{code},
	0,
	'send, then all of expect'
);
$return = $run->( 'tcp', '-H', '127.0.0.1', '-p', $plain_port, '-e', 'SSH-', '-t', 1 );
is( $return->{code}, 2, 'not what was expected' );
like( $return->{stdout}, qr/, did not get "SSH-", got "220 test ready"/, 'and what it got' );
like( $run->( 'tcp', '-H', '127.0.0.1', '-p', $closed_port )->{stdout},
	qr/\ATCP CRITICAL - 127.0.0.1:$closed_port, .*refused/i, 'refused' );
is(
	$run->( 'tcp', '-H', '127.0.0.1', '-p', $tls_port, '-S', '--ca-file', $paths->{ca} . '.pem', '-e', '* OK' )
		->{code},
	0,
	'over TLS'
);
like(
	$run->( 'tcp', '-H', '127.0.0.1', '-p', $tls_port, '-S', '-t', 2 )->{stdout},
	qr/\ATCP CRITICAL - .*verify failed/,
	'TLS with a untrusted certificate'
);
is( $run->( 'tcp', '-H', '127.0.0.1', '-p', $tls_port, '-S', '--insecure', '-e', '* OK' )->{code},
	0, 'TLS, --insecure' );
is( $run->( 'tcp', '-H', '127.0.0.1', '-p', 70000 )->{code}, 3, 'bad port' );

# https_cert
my @cert = ( '-H', '127.0.0.1', '-p', $tls_port, '--ca-file', $paths->{ca} . '.pem' );
$return = $run->( 'https_cert', @cert, '-n', 'www.example.org' );
is( $return->{code}, 1, '20 days left is WARNING' );
like(
	$return->{stdout},
	qr/\AHTTPS_CERT WARNING - 127.0.0.1:$tls_port "www.example.org" expires in 20 days, [0-9: -]+ UTC, issued by "Test CA" \| days=20;30;14\n\z/,
	'output'
);
is( $run->( 'https_cert', @cert, '-w', 10, '-c', 5 )->{code}, 0, 'OK, checked against the IP' );
is( $run->( 'https_cert', @cert, '-c', 25 )->{code}, 2, 'CRITICAL' );
like(
	$run->( 'https_cert', @cert, '-n', 'shop.example.org' )->{stdout},
	qr/\AHTTPS_CERT CRITICAL - .*hostname verification failed/,
	'name not covered'
);
like( $run->( 'https_cert', '-H', '127.0.0.1', '-p', $tls_port )->{stdout},
	qr/\AHTTPS_CERT CRITICAL - .*verify failed/, 'untrusted' );
is(
	$run->(
		'https_cert', '-H', '127.0.0.1', '-p', $tls_port, '--insecure', '-n', 'shop.example.org', '-w', 10, '-c', 5
	)->{code},
	0,
	'--insecure only checks the days'
);
like(
	$run->( 'https_cert', '-H', '127.0.0.1', '-p', $closed_port )->{stdout},
	qr/\AHTTPS_CERT CRITICAL - 127.0.0.1:$closed_port, /,
	'not connecting'
);
like(
	$run->( 'https_cert', '-H', '127.0.0.1', '-p', $plain_port, '-t', 2 )->{stdout},
	qr/\AHTTPS_CERT CRITICAL - /,
	'not TLS'
);

# STARTTLS
foreach my $protocol ( 'smtp', 'imap', 'pop3', 'ftp', 'ldap' ) {
	$return = $run->(
		'https_cert', '-H',      '127.0.0.1', '-p', $starttls_ports{$protocol},
		'-s',         $protocol, '--ca-file', $paths->{ca} . '.pem',
		'-w',         10,        '-c',        5
	);
	is( $return->{code}, 0, 'STARTTLS over ' . $protocol ) || diag( $return->{combined} );
}
like(
	$run->( 'https_cert', '-H', '127.0.0.1', '-p', $starttls_ports{smtp_no_tls}, '-s', 'smtp' )->{stdout},
	qr/\AHTTPS_CERT CRITICAL - 127.0.0.1:\d+ smtp does not offer STARTTLS\n\z/,
	'SMTP without STARTTLS'
);
like(
	$run->( 'https_cert', '-H', '127.0.0.1', '-p', $starttls_ports{ldap_refused}, '-s', 'ldap' )->{stdout},
	qr/ldap refused TLS, result code 52\n\z/,
	'LDAP refusing'
);
like(
	$run->( 'https_cert', '-H', '127.0.0.1', '-p', $plain_port, '-s', 'imap', '-t', 2 )->{stdout},
	qr/imap greeted with "220 test ready"/,
	'not IMAP'
);
like(
	$run->( 'https_cert', '-H', '127.0.0.1', '-p', $closed_port, '-s', 'smtp' )->{stdout},
	qr/\AHTTPS_CERT CRITICAL - 127.0.0.1:$closed_port, .*refused/i,
	'STARTTLS not connecting'
);
is( $run->( 'https_cert', '-H', '127.0.0.1', '-s', 'gopher' )->{code}, 3, 'bad --starttls' );

done_testing();
