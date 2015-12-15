#!/usr/bin/env perl

use warnings FATAL => 'all';
use strict;

my ($in_dir, $out_dir) = @ARGV;
my @files = <$in_dir/*.lua>;

sub quote_file {
    my ($in, $out) = @_;

    while (<$in>) {
        if (/^--.USE\s*"(\S+)"$/) {
            open(my $inc, '<', "$in_dir/$1.lua.in") or die "missing include $1";
            quote_file($inc, $out);
        }
        else {
            s/\"/\\"/g;
            s/^(.*)$/"$1\\n"/;
            print $out $_;
        }
    }
}

foreach my $file (@files) {
    if ($file =~ /([^\/.]+)(.lua)$/) {
        my $fname = "$1$2";
        my $varname = "rspamadm_script_$1";
        my $definename = uc $varname;

        open(my $in, '<', $file) or die "input missing";
        open(my $out, '>', "$out_dir/$fname.h") or die "output missing";

        print $out <<EOD;
#ifndef ${definename}_GUARD_H
#define ${definename}_GUARD_H

static const char ${varname}\[\] = ""
EOD
        quote_file($in, $out);

        print $out <<EOD;
"";
#endif
EOD
    }
}
