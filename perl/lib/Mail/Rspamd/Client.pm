
=head1 NAME

Mail::Rspamd::Client - Client for rspamd Protocol


=head1 SYNOPSIS

  my $client = new Mail::Rspamd::Client($config);

  if ($client->ping()) {
    $self->{error} = "Ping is ok\n";
  }

  my $result = $client->check($testmsg);

  if ($result->{'default'}->{isspam} eq 'True') {
    do something with spam message here
  }

=head1 DESCRIPTION

Mail::Rspamd::Client is a module that provides a perl implementation for
the spamd protocol.

=cut

package Mail::Rspamd::Client;

use IO::Socket;
use Carp;

use vars qw($VERSION);
$VERSION = "1.02";

my $EOL = "\015\012";
my $BLANK = $EOL x 2;
my $PROTOVERSION = 'RSPAMC/1.2';

=head1 PUBLIC METHODS

=head2 new

public class (Mail::Rspamd::Client) new (\% $args)

Description:
This method creates a new Mail::Rspamd::Client object.

=cut

sub new {
	my ($class, $args) = @_;

	$class = ref($class) || $class;

	my $self = {};

	# with a sockets_path set then it makes no sense to set host and port
	if ($args->{hosts}) {
		$self->{hosts} = $args->{hosts};
		$self->{alive_hosts} = $self->{hosts};
	}

	if ($args->{username}) {
		$self->{username} = $args->{username};
	}
	if ($args->{ip}) {
		$self->{ip} = $args->{ip};
	}
	if ($args->{from}) {
		$self->{from} = $args->{from};
	}
	if ($args->{subject}) {
		$self->{subject} = $args->{subject};
	}
	if ($args->{rcpt}) {
		$self->{rcpt} = $args->{rcpt};
	}
	if ($args->{deliver_to}) {
		$self->{deliver_to} = $args->{deliver_to};
	}
	if ($args->{timeout}) {
		$self->{timeout} = $args->{timeout};
	}
	else {
		$self->{timeout} = 5;
	}
	if ($args->{password}) {
		$self->{password} = $args->{password};
	}
	if ($args->{statfile}) {
		$self->{statfile} = $args->{statfile};
	}
	if ($args->{weight}) {
		$self->{weight} = $args->{weight};
	}
	else {
		$self->{weight} = 1;
	}
	if ($args->{pass_all}) {
		$self->{pass_all} = 1;
	}
	if ($args->{imap_search}) {
		$self->{imap_search} = $args->{imap_search};
	}
	else {
		$self->{imap_search} = 'ALL';
	}

	if ($args->{command}) {
		if ($args->{command} =~ /(SYMBOLS|PROCESS|CHECK|URLS|EMAILS)/i) {
			$self->{'command'} = $1;
			$self->{'control'} = 0;
		}
		elsif ($args->{command} =~ /(STAT|LEARN|SHUTDOWN|RELOAD|UPTIME|COUNTERS|FUZZY_ADD|FUZZY_DEL|WEIGHTS)/i) {
			$self->{'command'} = $1;
			$self->{'control'} = 1;
		}
	}

	$self->{error} = "";

	bless($self, $class);

	$self;
}


sub make_ssl_socket {
	my ($host, $port) = @_; 
	
	eval {
		require IO::Socket::SSL;
		IO::Socket::SSL->import(LIST);
	} or croak "IO::Socket::SSL required for imaps";

	return IO::Socket::SSL->new("$host:$port");
}



=head2 process_item

public instance (\%) process_item (String $item)

Description:
Do specified command for a single file, path or IMAP folder

The return value is a hash reference containing results of each command for each server from cluster

=cut

sub process_item {
	my $self = shift;
	my $item = shift;
	my $cb = shift;
	
	if (defined ($item)) {
		if ($item =~ qr|^imap(s?):user:([^:]+):password:([^:]*):host:([^:]+):mbox:(.+)$|) {
			return $self->_process_imap ($1, $2, $3, $4, $5, $cb);
		}
		elsif (-f $item) {
			return $self->_process_file ($item, $cb);
		}
		elsif (-d $item) {
			return $self->_process_directory ($item, $cb);
		}
		else {
			warn "urecognized argument: $item";
		}
	}
	undef;
}

=head2 process_path

public instance (\%) process_path ()

Description:
Do specified command for each file in path or message in IMAP folder

The return value is a hash reference containing results of each command for each server from cluster

=cut
sub process_path {
	my $self = shift;
	my $cb = shift;
	my %res;

	foreach (@_) {
		$res{$_} = $self->process_item($_, $cb);
	}

	return \%res;
}

=head2 do_all_cmd

public instance (\%) do_all_cmd (String $msg)

Description:
This method makes a call to the the whole rspamd cluster and call specified command
(in $self->{command}).

The return value is a hash reference containing results of each command for each server from cluster

=cut

sub do_all_cmd {
	my ($self, $input) = @_;

	my %res;
	
	if (!$self->{'hosts'} || scalar (@{ $self->{'hosts'} }) == 0) {
		$res{'error'} = 'Hosts list is empty';
		$res{'error_code'} = 404;
	}
	else {
		foreach my $hostdef (@{ $self->{'hosts'} }) {
			$self->_clear_errors();

			my $remote = $self->_create_connection($hostdef);

			if (! $remote) {
				$res{$hostdef}->{error_code} = 404;
				$res{$hostdef}->{error} = "Cannot connect to $hostdef";
			}
			else {
				if ($self->{'control'}) {
					$res{$hostdef} = $self->_do_control_command ($remote, $input);
				}
				else {
					$res{$hostdef} = $self->_do_rspamc_command ($remote, $input);
				}
			}
		}
	}

	return \%res;
}


=head2 check

public instance (\%) check (String $msg)

Description:
This method makes a call to the spamd server and depending on the value of
C<$is_check_p> either calls PROCESS or CHECK.

The return value is a hash reference containing metrics indexed by name. Each metric
is hash that contains data:

=over 
=item *
isspam

=item *
score

=item *
threshold

=item *
symbols - array of symbols

=back

=cut

sub check {
	my ($self, $msg) = @_;
	
	$self->{command} = 'CHECK';
	$self->{control} = 0;

	return $self->do_all_cmd ($msg);
}

=head2 symbols

public instance (\%) symbols (String $msg)

Description:
This method makes a call to the spamd server

The return value is a hash reference containing metrics indexed by name. Each metric
is hash that contains data:

=over
=item *
isspam

=item *
score

=item *
threshold

=item *
symbols - array of symbols

=back

=cut

sub symbols {
	my ($self, $msg) = @_;
	
	$self->{command} = 'SYMBOLS';
	$self->{control} = 0;

	return $self->do_all_cmd ($msg);
}

=head2 process

public instance (\%) process (String $msg)

Description:
This method makes a call to the spamd server

The return value is a hash reference containing metrics indexed by name. Each metric
is hash that contains data:

=over
=item *
isspam

=item *
score

=item *
threshold

=item *
symbols - array of symbols

=back

=cut
sub process {
	my ($self, $msg) = @_;
	
	$self->{command} = 'PROCESS';
	$self->{control} = 0;

	return $self->do_all_cmd ($msg);
}

=head2 emails

public instance (\%) emails (String $msg)

Description:
This method makes a call to the spamd server

The return value is a hash reference containing metrics indexed by name. Each metric
is hash that contains data:

emails - list of all emails in message
=cut
sub emails {
	my ($self, $msg) = @_;
	
	$self->{command} = 'EMAILS';
	$self->{control} = 0;

	return $self->do_all_cmd ($msg);
}

=head2 urls

public instance (\%) urls (String $msg)

Description:
This method makes a call to the spamd server

The return value is a hash reference containing metrics indexed by name. Each metric
is hash that contains data:

urls - list of all urls in message
=cut
sub urls {
	my ($self, $msg) = @_;
	
	$self->{command} = 'URLS';
	$self->{control} = 0;

	return $self->do_all_cmd ($msg);
}


=head2 learn

public instance (\%) learn (String $msg)

Description:
This method makes a call to the spamd learning a statfile with message.

=cut

sub learn {
	my ($self, $msg) = @_;
	
	$self->{command} = 'learn';
	$self->{control} = 1;

	return $self->do_all_cmd ($msg);
}

=head2 weights

public instance (\%) weights (String $msg)

Description:
This method makes a call to the spamd showing weights of message by each statfile.

=cut
sub weights {
	my ($self, $msg) = @_;
	
	$self->{command} = 'weights';
	$self->{control} = 1;

	return $self->do_all_cmd ($msg);
}

=head2 fuzzy_add

public instance (\%) fuzzy_add (String $msg)

Description:
This method makes a call to the spamd adding specified message to fuzzy storage.

=cut
sub fuzzy_add {
	my ($self, $msg) = @_;
	
	$self->{command} = 'fuzzy_add';
	$self->{control} = 1;

	return $self->do_all_cmd ($msg);
}
=head2 fuzzy_del

public instance (\%) fuzzy_add (String $msg)

Description:
This method makes a call to the spamd removing specified message from fuzzy storage.

=cut
sub fuzzy_del {
	my ($self, $msg) = @_;
	
	$self->{command} = 'fuzzy_del';
	$self->{control} = 1;

	return $self->do_all_cmd ($msg);
}

=head2 stat

public instance (\%) stat ()

Description:
This method makes a call to the spamd and get statistics.

=cut
sub stat {
	my ($self) = @_;
	
	$self->{command} = 'stat';
	$self->{control} = 1;

	return $self->do_all_cmd (undef);
}
=head2 uptime

public instance (\%) uptime ()

Description:
This method makes a call to the spamd and get uptime.

=cut
sub uptime {
	my ($self) = @_;
	
	$self->{command} = 'uptime';
	$self->{control} = 1;

	return $self->do_all_cmd (undef);
}
=head2 counters

public instance (\%) counters ()

Description:
This method makes a call to the spamd and get counters.

=cut
sub counters {
	my ($self) = @_;
	
	$self->{command} = 'counters';
	$self->{control} = 1;

	return $self->do_all_cmd (undef);
}

=head2 ping

public instance (Boolean) ping ()

Description:
This method performs a server ping and returns 0 or 1 depending on
if the server responded correctly.

=cut

sub ping {
	my $self = shift;
	my $host = shift;
	
	my $remote;
	$self->{control} = 0;
	if (defined($host)) {
		$remote = $self->_create_connection($host);
	}
	else {
		# Create connection to random host from cluster
		$remote = $self->_create_connection();
	}
	
	return undef unless $remote;
	local $SIG{PIPE} = 'IGNORE';

	if (!(syswrite($remote, "PING $PROTOVERSION$EOL"))) {
		$self->_mark_dead($remote);
		close($remote);
		return 0;
	}
	syswrite($remote, $EOL);

	return undef unless $self->_get_io_readiness($remote, 0);
	my $line;
	sysread ($remote, $line, 255);
	close $remote;
	return undef unless $line;

	my ($version, $resp_code, $resp_msg) = $self->_parse_response_line($line);
	return 0 unless (defined($resp_msg) && $resp_msg eq 'PONG');

	return 1;
}

=head1 PRIVATE METHODS

=head2 _create_connection

private instance (IO::Socket) _create_connection ()

Description:
This method sets up a proper IO::Socket connection based on the arguments
used when greating the client object.

On failure, it sets an internal error code and returns undef.

=cut

sub _create_connection {
	my ($self, $hostdef) = @_;

	my $remote;
	my $tries = 0;

	if (!defined ($hostdef)) {
		my $server;

		do {
			$server = $self->_select_server();
			$tries ++;
			
			if ($server->{host} eq '*') {
				$server->{host} = '127.0.0.1';	
			}
			$remote = IO::Socket::INET->new( Proto     => "tcp",
						PeerAddr  => $server->{host},
						PeerPort  => $server->{port},
						Blocking  => 0,
					);
			# Get write readiness
			if (defined ($remote)) {
				if ($self->_get_io_readiness($remote, 1) != 0) {
					return $remote;
				}
				else {
					close ($remote);
				}
			}
		} while ($tries < 5);

		return undef unless $server;
	}

    if ($hostdef =~ /^\//) {
        if (! socket ($remote, PF_UNIX, SOCK_STREAM, 0)) {
			print "Cannot create unix socket\n";
			return undef;
		}
        my $sun = sockaddr_un($hostdef);
        if (!connect ($remote, $sun)) {
			print "Cannot connect to socket $hostdef\n";
			close $remote;
			return undef;
		}
    }
    elsif ($hostdef =~ /^\s*(([^:]+):(\d+))\s*$/) {
		my $peer_addr = $2;
		if ($2 eq '*') {
			$peer_addr = '127.0.0.1';	
		}
		$remote = IO::Socket::INET->new( Proto     => "tcp",
					PeerAddr  => $peer_addr,
					PeerPort  => $3,
					Blocking  => 0,
				);
		# Get write readiness
		if (defined ($remote)) {
			if ($self->_get_io_readiness($remote, 1) != 0) {
				return $remote;
			}
			else {
				close ($remote);
				return undef;
			}
		}
    }
    elsif ($hostdef =~ /^\s*([^:]+)\s*$/) {
		my $peer_addr = $1;
		if ($1 eq '*') {
			$peer_addr = '127.0.0.1';	
		}
		$remote = IO::Socket::INET->new( Proto     => "tcp",
					PeerAddr  => $peer_addr,
					PeerPort  => $self->{control} ? 11334 : 11333,
					Blocking  => 0,
				);
		# Get write readiness
		if (defined ($remote)) {
			if ($self->_get_io_readiness($remote, 1) != 0) {
				return $remote;
			}
			else {
				close ($remote);
				return undef;
			}
		}
    }


	unless ($remote) {
		$self->{error} = "Failed to create connection to spamd daemon: $!\n";
		return undef;
	}
	$remote;
}

=head2 _auth

private instance (IO::Socket) _auth (Socket sock)

Description:
This method do control auth.

On failure this method returns 0

=cut
sub _auth {
	my ($self, $sock) = @_;

	local $SIG{PIPE} = 'IGNORE';

	if (!(syswrite($sock, "password $self->{password}$EOL"))) {
		$self->_mark_dead($remote);
		return 0;
	}

	return 0 unless $self->_get_io_readiness($sock, 0);

	if (sysread($sock, $reply, 255)) {
		if ($reply =~ /^password accepted/) {
			return 0 unless $self->_get_io_readiness($sock, 0);
			# read "END"
			sysread($sock, $reply, 255);
			return 1;
		}
	}

	return 0;
  
}

=head2 _revive_dead

private instance (IO::Socket) _revive_dead ()

Description:
This method marks dead upstreams as alive

=cut
sub _revive_dead {
	my ($self) = @_;

	my $now = time();
	foreach my $s ($self->{dead_hosts}) {
		# revive after minute of downtime
		if (defined($s->{dead}) && $s->{dead} == 1 && $now - $s->{t} > 60) {
			$s->{dead} = 0;
			push(@{$self->{alive_hosts}}, $s->{host});
		}
	}

  1;
}

=head2 _select_server

private instance (IO::Socket) _select_server ()

Description:
This method returns one server from rspamd cluster or undef if there are no suitable ones

=cut
sub _select_server {
	my($self) = @_;
	
	return undef unless $self->{alive_hosts};

	$self->_revive_dead();
	my $alive_num = scalar(@{$self->{alive_hosts}});
	if (!$alive_num) {
		$self->{alive_hosts} = $self->{hosts};
		$self->{dead_hosts} = ();
		$alive_num = scalar($self->{alive_hosts});
	}
	
	my $selected = $self->{alive_hosts}[int(rand($alive_num))];
	if ($selected =~ /^(\S+):(\d+)$/) {
		my $server = {
			host => $1,
			port => $2,
		};
		return $server;
	}

	undef;
}


=head2 _select_server

private instance (IO::Socket) _mark_dead (String server)

Description:
This method marks upstream as dead for some time. It can be revived by _revive_dead method

=cut
sub _mark_dead {
	my ($self, $server) = @_;
	
	return undef unless $self->{hosts};
	my $now = time();
	$self->{dead_hosts}->{$server} = {
		host => $server,
		dead => 1,
		t => $now,
	};
	for (my $i = 0; $i < scalar (@{$self->{alive_hosts}}); $i ++) {
		if ($self->{alive_hosts} == $server) {
			splice(@{$self->{alive_hosts}}, $i, 1);
			last;
		}
	}
}

=head2 _get_io_readiness

private instance (IO::Socket) _mark_dead (String server)

Description:
This method marks upstream as dead for some time. It can be revived by _revive_dead method

=cut
sub _get_io_readiness {
	my ($self, $sock, $is_write) = @_;
	my $w = '';
	vec($w, fileno($sock), 1) = 1;

	if ($is_write) {
		return select(undef, $w, undef, $self->{timeout});
	}
	else {
		return select($w, undef,undef, $self->{timeout});
	}
	
	undef;
}

=head2 _parse_response_line

private instance (@) _parse_response_line (String $line)

Description:
This method parses the initial response line/header from the server
and returns its parts.

We have this as a seperate method in case we ever decide to get fancy
with the response line.

=cut

sub _parse_response_line {
	my ($self, $line) = @_;

	$line =~ s/\r?\n$//;
	return split(/\s+/, $line, 3);
}

sub _write_message {
	my $self = shift;
	my $remote = shift;
	my $message = shift;
	my $len = shift;

	my $written = 0;

	while ($written < $len) {
		last unless ($self->_get_io_readiness($remote, 1));
		my $cur = syswrite $remote, $message, $len, $written;
		
		last if ($cur <= 0);
		$written += $cur;
	}

	return $written == $len;
}

=head2 _clear_errors

private instance () _clear_errors ()

Description:
This method clears out any current errors.

=cut

sub _clear_errors {
	my ($self) = @_;

	$self->{resp_code} = undef;
	$self->{resp_msg} = undef;
	$self->{error} = undef;
}

# Currently just read stdin for user's message and pass it to rspamd
sub _do_rspamc_command {
	my ($self, $remote, $msg) = @_;

	my %metrics;
	my ($in, $res);

	my $msgsize = length($msg);

	local $SIG{PIPE} = 'IGNORE';

	if (!(syswrite($remote, "$self->{command} $PROTOVERSION$EOL"))) {
		$self->_mark_dead($remote);
		my %r = (
			error => 'cannot connect to rspamd',
			error_code => 502,
		);
		close($remote);
		return \%r;
	}
	syswrite $remote, "Content-length: $msgsize$EOL";
	syswrite $remote, "User: $self->{username}$EOL" if (exists($self->{username}));
	syswrite $remote, "From: $self->{from}$EOL" if (exists($self->{from}));
	syswrite $remote, "IP: $self->{ip}$EOL" if (exists($self->{ip}));
	syswrite $remote, "Deliver-To: $self->{deliver_to}$EOL" if (exists($self->{deliver_to}));
	syswrite $remote, "Subject: $self->{subject}$EOL" if (exists($self->{subject}));
	syswrite $remote, "Pass: all$EOL" if (exists($self->{pass_all}) && $self->{pass_all});
	if (ref $self->{rcpt} eq "ARRAY") {
		foreach ($self->{rcpt}) {
			syswrite $remote, "Rcpt: $_ $EOL";
		}
	}
	syswrite $remote, $EOL;

	if (! $self->_write_message($remote, $msg, $msgsize)) {
		my %r = (
			error => 'error writing message to rspamd',
			error_code => 502,
		);
		close $remote;
		return \%r;
	}

	#syswrite $remote, $EOL;
	
	unless ($self->_get_io_readiness($remote, 0)) {
		close $remote;
		my %r = (
			error => 'timed out while waiting for reply',
			error_code => 502,
		);
		return \%r;
	}
			
	my $offset = 0;
	do {
		$res = sysread($remote, $in, 512, $offset);
		if (!defined ($res)) {
			close $remote;
			my %r = (
				error => 'IO error while reading data from socket: ' . $!,
				error_code => 503,
			);
			return \%r;
		}
		if ($res > 0 && $res < 512) {
			$self->_get_io_readiness($remote, 0);
		}
		$offset += $res;
	} while ($res > 0);

	my ($version, $resp_code, $resp_msg) = $self->_parse_response_line($in);

	$self->{resp_code} = $resp_code;
	$self->{resp_msg} = $resp_msg;

	unless (defined($resp_code) && $resp_code == 0) {
		close $remote;
		my %r = (
			error => 'invalid reply',
			error_code => 500,
		);
		return \%r
	}

	my $cur_metric;
	my @lines = split (/^/, $in);
	if (lc $self->{'command'} eq 'urls') {
		$metrics{'default'} = {
			isspam => 'false',
			score => 0,
			threshold => 0,
			symbols => [],
			urls => [],
			messages => [],
			action => 'reject',
		};
		foreach my $line (@lines) {
			if ($line =~ /^Urls: (.+)$/) {
				@{ $metrics{'default'}->{'urls'} } = split /,\s+/, $1;
			}
		}
	}
	else {
		foreach my $line (@lines) {
			if ($line =~ m!Metric: (\S+); (\S+); (\S+) / (\S+) (/ (\S+))?!) {
				$metrics{$1} = {
					isspam => $2,
					score => $3 + 0,
					threshold => $4 + 0,
					reject_score => $6,
					symbols => [],
					urls => [],
					messages => [],
					action => 'no action',
				};
				$cur_metric = $1;
			}
			elsif ($line =~ /^Symbol: (\S+);\s*(.+?)\s*$/ && $cur_metric) {
				# Line with parameters
				my $symref = $metrics{$cur_metric}->{'symbols'};
				push(@$symref, "$1($2)");
			}
			elsif ($line =~ /^Symbol: (\S+?)\s*$/ && $cur_metric) {
				my $symref = $metrics{$cur_metric}->{'symbols'};
				push(@$symref, $1);
			}
			elsif ($line =~ /^Urls: (.+?)\s*$/ && $cur_metric) {
				@{ $metrics{$cur_metric}->{'urls'} } = split /,\s+/, $1;
			}
			elsif ($line =~ /^Message: (.+?)\s*$/ && $cur_metric) {
				my $symref = $metrics{$cur_metric}->{'messages'};
				push(@$symref, $1);
			}
			elsif ($line =~ /^Action: (.+?)\s*$/ && $cur_metric) {
				$metrics{$cur_metric}->{'action'} = $1;
			}
			elsif ($line =~ /^${EOL}$/) {
				last;
			}
		}
	}

	close $remote;

	return \%metrics;

}


sub _do_control_command {
	my ($self, $remote, $msg) = @_;

	local $SIG{PIPE} = 'IGNORE';
	my %res = (
		error_code	=> 0,
		error		=> '',
	);

	unless ($self->_get_io_readiness($remote, 0)) {
		$res{error} = "Timeout while reading data from socket";
		$res{error_code} = 501;
		close($remote);
		return \%res;
	}

    # Read greeting first
    if (defined (my $greeting = <$remote>)) {
        if ($greeting !~ /^Rspamd version/) {
            $res{error} = "Not rspamd greeting line $greeting";
			$res{error_code} = 500;
			close($remote);
			return \%res;
        }
    }

    if ($self->{'command'} =~ /^learn$/i) {
        if (!$self->{'statfile'}) {
			$res{error} = "Statfile is not specified to learn command";
			$res{error_code} = 500;
			close($remote);
			return \%res;
		}
        
        if ($self->_auth ($remote)) {
            my $len = length ($msg);
            syswrite $remote, "learn $self->{statfile} $len -m $self->{weight}" . $EOL;
			if (! $self->_write_message($remote, $msg, length($msg))) {
				$res{error} = 'error writing message to rspamd';
				$res{error_code} = 502;
				close $remote;
				return \%res;
			}
			unless ($self->_get_io_readiness($remote, 0)) {
				$res{error} = "Timeout while reading data from socket";
				$res{error_code} = 501;
				close($remote);
				return \%res;
			}
            if (defined (my $reply = <$remote>)) {
                if ($reply =~ /^learn ok, sum weight: ([0-9.]+)/) {
                    $res{error} = "Learn succeed. Sum weight: $1\n";
					close($remote);
					return \%res;
                }
                else {
					$res{error_code} = 500;
                    $res{error} = "Learn failed: $reply\n";
					close($remote);
					return \%res;
                }
            }
        }
        else {
			$res{error_code} = 403;
            $res{error} = "Authentication failed\n";
			close($remote);
			return \%res;
        }
    }
    elsif ($self->{'command'} =~ /^weights$/i) {
        if (!$self->{'statfile'}) {
			$res{error_code} = 500;
			$res{error} = "Statfile is not specified to weights command";
			close($remote);
			return \%res;
		}
        
		my $len = length ($msg);
		$res{error} = "Sending $len bytes...\n";
		syswrite $remote, "weights $self->{'statfile'} $len" . $EOL;
		if (! $self->_write_message($remote, $msg, length($msg))) {
			$res{error} = 'error writing message to rspamd';
			$res{error_code} = 502;
			close $remote;
			return \%res;
		}
		unless ($self->_get_io_readiness($remote, 0)) {
			$res{error} = "Timeout while reading data from socket";
			$res{error_code} = 501;
			close($remote);
			return \%res;
		}
		while (defined (my $reply = <$remote>)) {
			last if $reply =~ /^END/;
			$res{error} .= $reply;
		}
    }
    elsif ($self->{'command'} =~ /(reload|shutdown)/i) {
        if ($self->_auth ($remote)) {
            syswrite $remote, $self->{'command'} . $EOL;
			unless ($self->_get_io_readiness($remote, 0)) {
				$res{error} = "Timeout while reading data from socket";
				$res{error_code} = 501;
				close($remote);
				return \%res;
			}
            while (defined (my $line = <$remote>)) {
                last if $line =~ /^END/;
                $res{error} .= $line;
            }
        }
        else {
			$res{error_code} = 403;
            $res{error} = "Authentication failed\n";
			close($remote);
			return \%res;
        }
    }
    elsif ($self->{'command'} =~ /(fuzzy_add|fuzzy_del)/i) {
        if ($self->_auth ($remote)) {
            my $len = length ($msg);
            syswrite $remote, $self->{'command'} . " $len $self->{'weight'}" . $EOL;
			if (! $self->_write_message($remote, $msg, length($msg))) {
				$res{error} = 'error writing message to rspamd';
				$res{error_code} = 502;
				close $remote;
				return \%res;
			}
			unless ($self->_get_io_readiness($remote, 0)) {
				$res{error} = "Timeout while reading data from socket";
				$res{error_code} = 501;
				close($remote);
				return \%res;
			}
            if (defined (my $reply = <$remote>)) {
                if ($reply =~ /^OK/) {
                    $res{error} = $self->{'command'} . " succeed\n";
					close($remote);
					return \%res;
                }
                else {
					$res{error_code} = 500;
                    $res{error} = $self->{'command'} . " failed\n";
					close($remote);
					return \%res;
                }
            }
        }
        else {
			$res{error_code} = 403;
            $res{error} = "Authentication failed\n";
			close($remote);
			return \%res;
        }
    
    }
    else {
        syswrite $remote, $self->{'command'} . $EOL;
		unless ($self->_get_io_readiness($remote, 0)) {
			$res{error} = "Timeout while reading data from socket";
			$res{error_code} = 501;
			close($remote);
			return \%res;
		}
        while (defined (my $line = <$remote>)) {
            last if $line =~ /^END/;
            $res{error} .= $line;
        }
    }

	close($remote);
	return \%res;
}

sub _process_file {
	my $self = shift;
	my $file = shift;
	my $cb = shift;
	my $res;

	open(FILE, "< $file") or return;
	
	my $input;
	while (defined (my $line = <FILE>)) {
		$input .= $line;
	}
	
	close FILE;
	$res = $self->do_all_cmd ($input);
	if (defined ($cb) && $res) {
		$cb->($file, $res);
	}
}

sub _process_directory {
	my $self = shift;
	my $dir = shift;
	my $cb = shift;

	opendir (DIR, $dir) or return;

	while (defined (my $file = readdir (DIR))) {
		$file = "$dir/$file";
		if (-f $file) {
			$self->_process_file ($file, $cb);
		}	
	}
	closedir (DIR);
}

sub _check_imap_reply {
	my $self = shift;
	my $sock = shift;
	my $seq = shift;

	my $input;

	while (defined ($input = <$sock>)) {
		chomp $input;
		if ($input =~ /BAD|NO (.+)$/) {
			$_[0] = $1;
			return 0;
		}
		next if ($input =~ /^\*/);
		if ($input =~ /^$seq OK/) {
			return 1;
		}

		$_[0] = $input;
		return 0;
	}

	$_[0] = "timeout";
	
	return 0;
}

sub _parse_imap_body {
	my $self = shift;
	my $sock = shift;
	my $seq = shift;
	my $input;
	my $got_body = 0;

	while (defined (my $line = <$sock>)) {
		if (!$got_body && $line =~ /^\*/) {
			$got_body = 1;
			next;
		}
		if ($line =~ /^$seq OK/) {
			return $input;
		}
		elsif ($got_body) {
			$input .= $line;
			next;
		}
		
		return undef;
	}

	return undef;

}

sub _parse_imap_sequences {
	my $self = shift;
	my $sock = shift;
	my $seq = shift;
	my $input;

	while (defined ($input = <$sock>)) {
		chomp $input;
		if ($input =~ /^\* SEARCH (.+)$/) {
			@res = split (/\s/, $1);
			next;
		}
		elsif ($input =~ /^$seq OK/) {
			return \@res;
		}
		return undef;
	}

}

sub _process_imap {
	my ($self, $ssl, $user, $password, $host, $mbox, $cb) = @_;
	my $seq = 1;
	my $sock;
	my $res;

	if (!$password) {
		eval {
			require Term::ReadKey;
			Term::ReadKey->import( qw(ReadMode ReadLine) );
			print "Enter IMAP password: ";
			ReadMode(2);
			$password = ReadLine(0);
			chomp $password;
			ReadMode(0);
			print "\n";
		} or croak "cannot get password. Check that Term::ReadKey is installed";
	}

	# Stupid code that does not take care of timeouts etc, just trying to extract messages
	if ($ssl) {
		$sock = $self->_make_ssl_socket ($host, 'imaps');
	}
	else {
		$sock = IO::Socket::INET->new( Proto     => "tcp",
						PeerAddr  => $host,
						PeerPort  => 'imap',
						Blocking  => 1,
					);
	}
	unless ($sock) {
		$self->{error} = "Cannot connect to imap server: $!";
		return;
	}
	my $reply = <$sock>;
	if (!defined ($reply) || $reply !~ /^\* OK/) {
		$self->{error} = "Imap server is not ready";
		return;
	}
	syswrite $sock, "$seq LOGIN $user $password$EOL";
	if (!$self->_check_imap_reply ($sock, $seq, $reply)) {
		$self->{error} = "Cannot login to imap server: $reply";
		return;
	}
	$seq ++;
	syswrite $sock, "$seq SELECT $mbox$EOL";
	if (!$self->_check_imap_reply ($sock, $seq, $reply)) {
		$self->{error} = "Cannot select mbox $mbox: $reply";
		return;
	}
	$seq ++;
	syswrite $sock, "$seq SEARCH $self->{imap_search}$EOL";
	my $messages;
	if (!defined ($messages = $self->_parse_imap_sequences ($sock, $seq))) {
		$self->{error} = "Cannot make search";
		return;
	}
	$seq ++;
	foreach my $message (@{ $messages }){
		syswrite $sock, "$seq FETCH $message body[]$EOL";
		if (defined (my $input = $self->_parse_imap_body ($sock, $seq))) {
			$self->do_all_cmd ($input);
			if (defined ($cb) && $res) {
				$cb->($seq, $res);
			}
		}
		$seq ++;
	} 
	syswrite $sock, "$seq LOGOUT$EOL";
	close $sock;
}

1;
