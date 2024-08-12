#!/usr/bin/env perl

use warnings;
use strict;
use Net::IDN::Encode ':all';
use Unicode::Normalize;

binmode(STDOUT, ":utf8");
binmode(STDIN, ":utf8");

while (<>) {
	$_ = NFC($_);
	if (/^[^\/].*[^\x00-\x7F]+.*/) {
		chomp;
		printf "%s\n", domain_to_ascii($_);
		$_ .= "\n";
	}
} continue {
	print $_;
}