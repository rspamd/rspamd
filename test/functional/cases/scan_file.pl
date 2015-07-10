#!/usr/bin/env perl

use warnings;
use strict;

use Socket;

my $host = "127.0.0.1";
my $port = 56789;
my $input_file = shift;

socket(SOCKET,PF_INET,SOCK_STREAM,(getprotobyname('tcp'))[2])
   or die "Can't create a socket $!\n";
connect(SOCKET, pack_sockaddr_in($port, inet_aton($host)))
   or die "Can't connect to port $port! \n";

print SOCKET "GET /symbols?${input_file} HTTP/1.0\r\n\r\n";

SOCKET->autoflush(1);

shutdown(SOCKET, 1);

while (my $line = <SOCKET>) {
	print $line;
}

close(SOCKET);

