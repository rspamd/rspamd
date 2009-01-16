#!/usr/bin/perl -w

# Simple script that read message from STDIN and test it on rspamd server
# using specified command.
#
# Usage: rspamc.pl [-c conf_file] [command]
#
# By default rspamc.pl would read ./rspamd.conf and default command is SYMBOLS

use Socket qw(:DEFAULT :crlf);

my %cfg = (
    'conf_file' => './rspamd.conf',
    'command'   => 'SYMBOLS',
    'host'      => 'localhost',
    'port'      => '11333',
    'is_unix'   => 0,
);

sub usage {
    return "Usage: rspamc.pl [-c conf_file] [command]";
}

while (my $param = shift) {
    if ($param eq '-c') {
        my $value = shift;
        if ($value) {
            if (-r $value) {
                $cfg{'conf_file'} = $value;
            }
            else {
                die "config file $value is not readable";
            }
        }
        else {
            die usage();
        }
    }
    elsif ($param =~ /(SYMBOLS|SCAN|PROCESS|CHECK|REPORT_IFSPAM|REPORT)/i) {
        $cfg{'command'} = $1;
    }
}

open CONF, "< $cfg{'conf_file'}" or die "config file $cfg{'conf_file'} cannot be opened";

my $ctrl = 0;
while (<CONF>) {
    if ($_ =~ /control\s*{/i) {
        $ctrl = 1;
    }
    if ($ctrl && $_ =~ /}/) {
        $ctrl = 0;
    }
    if (!$ctrl && $_ =~ /^\s*bind_socket\s*=\s*((([^:]+):(\d+))|(\/\S*))/i) {
        if ($3 && $4) {
            $cfg{'host'} = $3;
            $cfg{'port'} = $4;
            $cfg{'is_unix'} = 0;
        }
        else {
            $cfg{'host'} = $5;
            $cfg{'is_unix'} = 1;
        }
        last;
    }
}

close CONF;

if ($cfg{'is_unix'}) {
    my $proto = getprotobyname('tcp');
    socket (SOCK, PF_UNIX, SOCK_STREAM, $proto) or die "cannot create unix socket";
    my $sun = sockaddr_un($cfg{'host'});
    connect (SOCK, $sun) or die "cannot connect to socket $cfg{'host'}";
}
else {
    my $proto = getprotobyname('tcp');
    my $sin;
    socket (SOCK, PF_INET, SOCK_STREAM, $proto) or die "cannot create tcp socket";
    if (inet_aton ($cfg{'host'})) {
        $sin = sockaddr_in ($cfg{'port'}, inet_aton($cfg{'host'}));
    }
    else {
        my $addr = gethostbyname($cfg{'host'});
        if (!$addr) {
            die "cannot resolve $cfg{'host'}";
        }
        $sin = sockaddr_in ($cfg{'port'}, $addr);
    }
    
    connect (SOCK, $sin) or die "cannot connect to socket $cfg{'host'}:$cfg{'port'}";
}

my $input;
while (defined (my $line = <>)) {
    $input .= $line;
}

print "Sending ". length ($input) ." bytes...\n";

syswrite SOCK, "$cfg{'command'} RSPAMC/1.0 $CRLF";
syswrite SOCK, "Content-Length: " . length ($input) . $CRLF . $CRLF;
syswrite SOCK, $input;
syswrite SOCK, $CRLF;
while (<SOCK>) {
    print $_;
}
close SOCK;
