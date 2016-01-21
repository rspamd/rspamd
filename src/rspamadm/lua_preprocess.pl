#!/usr/bin/env perl

use warnings FATAL => 'all';
use strict;
use Digest::MD5;

my ( $in_dir, $out_dir ) = @ARGV;
my @files = <$in_dir/*.lua>;

sub quote_file {
	my ( $in, $out ) = @_;

	while (<$in>) {
		if (/^--.USE\s*"(\S+)"$/) {
			open( my $inc, '<', "$in_dir/$1.lua.in" )
			  or die "missing include $1";
			quote_file( $inc, $out );
		}
		else {
			s/^\s*//;    # remove unnecessary spaces at the beginning
			next if /^--/;      # skip comments
			next if /^\s*$/;    # skip empty lines
			s/(.)/'$1',/g;          # split as 'c',
			s/\'\\\'/\'\\\\'/g;     # escape backslashes
			s/\'\'\'/\'\\\'\'/g;    # escape single quotes
			print $out "$_'\\n',";
		}
	}
}

sub digest_for_file {
	my ($file) = @_;

	open( my $in, '<', $file ) or die "file missing";
	my $digest = Digest::MD5->new->addfile($in)->hexdigest;

	return $digest;
}

sub changed {
	my ( $file, $outfile ) = @_;

	open( my $out, '<', $outfile ) or return 1;

	my $in_checksum = digest_for_file($file);
	my $ln          = <$out>;

	if ( $ln =~ /^.*id:(\S+)\s.*$/ ) {
		if ( $in_checksum ne $1 ) {
			return 1;
		}
		else {
			return 0;
		}
	}

	return 1;
}

foreach my $file (@files) {
	if ( $file =~ /([^\/.]+)(.lua)$/ ) {
		my $fname      = "$1$2";
		my $varname    = "rspamadm_script_$1";
		my $definename = uc $varname;
		my $outfile    = "$out_dir/$fname.h";

		if ( changed( $file, $outfile ) ) {
			open( my $in,  '<', $file )    or die "input missing";
			open( my $out, '>', $outfile ) or die "output missing";
			my $checksum = digest_for_file($file);
			print $out <<EOD;
/* id:$checksum */
#ifndef ${definename}_GUARD_H
#define ${definename}_GUARD_H

static const char ${varname}\[\] = {
EOD
			quote_file( $in, $out );

			print $out <<EOD;
'\\0'};
#endif
EOD
		}
	}
}
