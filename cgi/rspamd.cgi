#!/usr/bin/perl -w

use strict;
use warnings;

{

package RspamdWebInterface;

use strict;
use Mail::Rspamd::Client;
use CGI qw/:standard -debug/;
use IO::Socket::INET;
use IO::String;
use Data::Dumper;

my %cfg = (
	'hosts'      => ['localhost:11333'],
	'timeout'	=> 1,
	'password'	=> '',
	'statfiles' => ['WINNOW_HAM', 'WINNOW_SPAM'],
);

sub new {
	my ($class, $args) = @_;

	$class = ref($class) || $class;

	my $self = {
		addr => 'localhost',
		port => 8080,
		standalone => 0,
	};

	if ($args->{'standalone'}) {
		$self->{'standalone'} = 1;
	}
	if ($args->{'port'}) {
		$self->{'port'} = $args->{'port'};
	}
	if ($args->{'addr'}) {
		$self->{'addr'} = $args->{'addr'};
	}
	if ($args->{'config'}) {
		open CFG, "< $args->{'config'}";
		my $cf;
		$cfg{'hosts'} = [];
		while (<CFG>) {
			chomp;
			push (@{$cfg{'hosts'}}, $_); 
		}
		close CFG;
	}

	bless($self, $class);

	$self;
}

sub _handle_ping {
	my $self = shift;
	my (@servers_alive, @servers_dead);
	
	my $rspamd = Mail::Rspamd::Client->new({timeout=>$cfg{timeout}});
	my $number = 0;

	# Walk throught selection of servers
	foreach (@{ $cfg{'hosts'} }) {
		if ($rspamd->ping($_)) {
			push(@servers_alive, $_);
		}
		else {
			push(@servers_dead, $_);
		}
		$number ++;
	}
	
	print header;
	print qq!<select multiple="multiple" id="id_servers" name="servers" size="$number">!;
	
	foreach (@servers_alive) {
		print qq!<option value="$_" style="color:#8CC543">$_</option>!;
	}
	foreach (@servers_dead) {
		print qq!<option value="$_" style="color:#C51111" disable="disable">$_</option>!;
	}
	print "</select>";

}

sub _show_html {
	my $self = shift;

	print header,
	  start_html(-title=>'Rspamd control', -script=>[{-type=>'JAVASCRIPT', -src=>'http://www.google.com/jsapi'},
				{-type=>'JAVASCRIPT', -code=>'google.load("jquery", "1");'}]),
	  h1('Manage rspamd cluster'),
	  start_form(-method=>'POST', -enctype=>&CGI::MULTIPART),
	  "<label for=\"id_servers\">Servers:</label>",
	  "<div id=\"servers_div\">",
	  scrolling_list(-name => 'servers',  
		             -multiple=>'true',
					 -values=>$cfg{'hosts'},
					 -id=>'id_servers',
					),
	  "</div>",
	  button(-name=>'ping',
             -value=>'Ping',
             -onClick=>'$.ajax({
					url: \'/ajax\',
					success: function(data) {
						$(\'#servers_div\').html(data);
					}
			});'),
	  br,
	  "<label for='id_command'>Command:</label>",
	  popup_menu (-name=>'command',
			      -values=>['symbols', 'check', 'stat', 'learn', 'fuzzy_add', 'fuzzy_del', 'weights', 'uptime'],
				  -labels=> { 
					  'symbols'=>'Scan symbols for message',
					  'check'=>'Check if message is spam',
					  'stat'=>'Check statistics',
					  'learn'=>'Learn rspamd with message',
					  'fuzzy_add'=>'Add fuzzy hash',
					  'fuzzy_del'=>'Delete fuzzy hash',
					  'weights'=>'Check weights of message',
					  'uptime'=>'Get uptime',
				  },
				  -id=>'id_command',
			     ),
	  br,
	  "<label for=\"id_statfile\">Statfile:</label>",
	  popup_menu(-name=>'statfile', -id=>'id_statfile', -values=>$cfg{'statfiles'}),
	  br,
	  "<label for=\"id_file\">File:</label>",
	  filefield(-name=>'upload_file', -id=>'id_file'),
	  br,
	  "<label for=\"id_message\">Message text:</label>",
	  textarea(-name=>'message', -id=>'id_message', -rows=>10, -columns=>80),
	  br,
	  "<label for=\"id_weight\">Weight of learn:</label>",
	  textfield(-name=>'weight', -id=>'id_weight'),
	  br,
	  submit,
      end_form;

	print end_html;
}

sub _get_file {
	my $self = shift;
	my $fh = shift;

	my $output;
	my $buffer;

	if (! $fh) {
		return undef;
	}
	my $io_handle = $fh->handle;

    while (my $bytesread = $io_handle->read($buffer,1024)) {
		$output .= $buffer;
	}

	return $output;
}


sub _make_rfc822_message {
	my $self = shift;
	my $msg = shift;
	
	# Check whether first line is a header line 
	if ($msg =~ /^[^:]+:\s*\S+$/) {
		# Assume that message has all headers
		return $msg;
	}
	else {
		my $output = <<EOT;
Received: from localhost (localhost [127.0.0.1])
	by localhost (Postfix) with ESMTP id 5EC0D146;
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 8bit
Date: Thu, 1 Jan 1970 00:00:00 +0000
From: auto\@non-existent.com
Message-Id: <auto\@non-existent.com>

$msg
EOT
		return $output;
	}
}

sub _get_message {
	my $self = shift;
	my $cgi = shift;

	if ($cgi->param('upload_file')) {
		return $self->_get_file($cgi->upload('upload_file'));
	}
	elsif (my $msg = $cgi->param('message')) {
		return $self->_make_rfc822_message ($msg);
	}

	undef;
}

sub _show_rspamc_result {
	my $self = shift;
	my $host = shift;
	my $res = shift;
	
	if (defined($res->{error})) {
		print "<p><strong>Error occured:</strong>&nbsp;$res->{error}</p>";
	}
	else {
		while (my ($metric, $result) = each (%{ $res })) {
			print "<p><strong>Metric:</strong>&nbsp;$metric</p>";
			print "<p><strong>Summary:</strong>&nbsp;$result->{isspam}, [ $result->{score} / $result->{threshold} ]</p>";
			print "<p><strong>Symbols:</strong>&nbsp;";
			print join("; ", @{ $result->{symbols} }) . "</p>";
			print "<p><strong>Urls:</strong>&nbsp;" . join(", ", @{ $result->{urls} }) . "</p>";
			foreach my $msg (@{ $result->{messages} }) {
				print "<p><strong>Message:</strong>&nbsp;$msg</p>";
			}
			print br;
		}
	}
}

sub _show_error {
	my $self = shift;
	my $error = shift;

	print header,
	  start_html(-title=>'Rspamd control', -script=>[{-type=>'JAVASCRIPT', -src=>'http://www.google.com/jsapi'},
				{-type=>'JAVASCRIPT', -code=>'google.load("jquery", "1");'}]),
	  h1('Results for rspamd command'),
	  "<p><strong>Error occured:</strong>&nbsp;$error</p>",
	  '<a href="javascript:history.back()">Back to manage</a>',
	  end_html;
}

sub _show_control_result {
	my $self = shift;
	my $host = shift;
	my $res = shift;
	
	if ($res->{error_code} == 0) {
		print "<p><pre>$res->{error}</pre></p>";
	}
	else {
		print "<p><strong>Error occured:</strong>&nbsp;$res->{error}</p>";
	}
}

sub _show_results {
	my $self = shift;
	my $rspamd = shift;
	my $res = shift;

	if (defined ($res->{error})) {
		$self->_print_error($res->{error});
		return;
	}
	print header,
	  start_html(-title=>'Rspamd control', -script=>[{-type=>'JAVASCRIPT', -src=>'http://www.google.com/jsapi'},
				{-type=>'JAVASCRIPT', -code=>'google.load("jquery", "1");'}]),
	  h1('Results for rspamd command: ' . $rspamd->{command});

	while (my ($host, $result) =  each (%{ $res })) {
		print h2('Results for host: ' . $host);
		if ($rspamd->{control}) {
			$self->_show_control_result ($host, $result);
		}
		else {
			$self->_show_rspamc_result ($host, $result);
		}
		print hr;
	}

	print '<a href="javascript:history.back()">Back to manage</a>';
	print end_html;
}

sub _handle_form {
	my $self = shift;
	my $cgi = shift;
	
	my @servers = $cgi->param('servers');
	if (!@servers || scalar(@servers) == 0) {
		@servers = @{ $cfg{'hosts'} };
	}
	my $rspamd = Mail::Rspamd::Client->new({hosts => \@servers, timeout=>$cfg{timeout}, password=>$cfg{password}});
	my $cmd = $cgi->param('command');
	if (!$cmd) {
		return undef;
	}

	my $results;

	if($cmd eq 'symbols' || $cmd eq 'check') {
		my $msg = $self->_get_message($cgi);
		return undef unless $msg;
		$results = $rspamd->$cmd($msg);
	}
	elsif ($cmd eq 'learn') {
		my $statfile = $cgi->param('statfile');
		return undef unless $statfile;
		my $msg = $self->_get_message($cgi);
		return undef unless $msg;

		$rspamd->{'statfile'} = $statfile;
		if (my $weight = $cgi->param('weight')) {
			$rspamd->{'weight'} = int($weight);
		}

		$results = $rspamd->learn($msg);
	}
	elsif ($cmd eq 'fuzzy_add' || $cmd eq 'fuzzy_del') {
		my $msg = $self->_get_message($cgi);
		return undef unless $msg;
		if (my $weight = $cgi->param('weight')) {
			$rspamd->{'weight'} = int($weight);
		}

		$results = $rspamd->$cmd($msg);
	}
	elsif ($cmd eq 'stat' || $cmd eq 'uptime') {
		$results = $rspamd->$cmd();
	}

	$self->_show_results($rspamd, $results);

}

sub _handle_request {
	my $self = shift;
	my $cgi  = shift;
   
	my $path = $cgi->path_info();
	unless ($path) {
		print "CGI environment missing\n";
		return undef;
	}

	print "HTTP/1.0 200 OK\r\n";

	if ($cgi->request_method() eq 'POST') {
		if (!$self->_handle_form($cgi)) {
			$self->_show_error("invalid command");
		}
	}
	else {
		if ($path =~ '^/ajax$') {
			$self->_handle_ping();
		}
		else {
			$self->_show_html();
		}
	}
}

sub _run_standalone {
	my $self = shift;
	my $listen = IO::Socket::INET->new(
		Listen    => 5,
		LocalAddr => $self->{addr},
		LocalPort => $self->{port},
		Proto     => 'tcp',
		ReuseAddr => 1
	);

	unless ($listen) {
		warn "unable to listen on port $self->{port}: $!\n";
		return undef;
	};

	print STDERR "waiting for connection on port $self->{port}\n";
	while (1) {
		my $s = $listen->accept();

		open(STDOUT, ">&=".fileno($s));
		open(STDIN, "<&=".fileno($s));

		my ($req, $content);
		delete $ENV{CONTENT_LENGTH};
		{ 
			local ($/) = "\r\n";
			while (<STDIN>) {
				$req .= $_;
				chomp;
				last unless /\S/;
				if (/^GET\s*(\S+)/) {
					$ENV{REQUEST_METHOD} = 'GET';
					my ($pi, $qs) = split /\?/, $1, 2;
					$ENV{'PATH_INFO'} = $pi;
					$ENV{'QUERY_STRING'} = $qs;
				} elsif (/^POST\s*(\S+)/) {
					$ENV{REQUEST_METHOD} = 'POST';
					my ($pi, $qs) = split /\?/, $1, 2;
					$ENV{'PATH_INFO'} = $pi;
					$ENV{'QUERY_STRING'} = $qs;
				} elsif (/^Content-Type:\s*(.*)/) {
					$ENV{CONTENT_TYPE} = $1;
				} elsif (/^Content-Length:\s*(.*)/) {
					$ENV{CONTENT_LENGTH} = $1;
				}
			}
		}
		$ENV{SERVER_PORT} = $self->{port};
		$ENV{SERVER_NAME} = $self->{addr};
		if (my $size = $ENV{CONTENT_LENGTH}) {
			$content = '';
			while (length($content) < $size) {
				my $nr = read(STDIN, $content, $size-length($content),
							length($content));
				warn "read error" unless $nr;
			}
		}
		

		close(STDIN); # n.b.: does not close socket
		tie *STDIN, 'IO::String', $content;

		undef @CGI::QUERY_PARAM;
		my $q = new CGI();
		$self->_handle_request($q);

		untie *STDIN;
		close(STDOUT);
		close($s);
	}
}

sub run {
	my $self = shift;

	if ($self->{'standalone'} != 0) {
		$self->_run_standalone();
	}
	else {
		my $q = new CGI();
		$self->_handle_request($q);
	}
}

}

# Parse arguments

my ($port, $standalone, $cfg, $host);

while (my $arg = shift @ARGV) {
	if ($arg =~ /^-port$/i) {
		$port = shift @ARGV;
	}
	elsif ($arg =~ /^-standalone$/i) {
		$standalone = 1;
	}
	elsif ($arg =~ /^-cfg$/i) {
		$cfg = shift @ARGV;
	}
	elsif ($arg =~ /^-host$/i) {
		$host = shift @ARGV;
	}
	else {
		print STDERR <<EOT;
Rspamd.cgi is a simple web intraface for managing rspamd cluster.
Usage: rspamd.cgi [-standalone] [-host hostname] [-port number] [-cfg config_file]
Options allowed:
-standalone                  Start rspamd.cgi as standalone http server (for testing)
-port                        Port to run standalone server
-host                        Host to run standalone server
-cfg                         Config file (in perl) that redefines defaults
EOT
		exit;
	}
}

$port = 8080 unless int($port);
$host = 'localhost' unless $host;

RspamdWebInterface->new({port=>$port, standalone=>$standalone, config=>$cfg, addr=>$host})->run();
