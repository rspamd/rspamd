#!/usr/bin/env perl

use warnings FATAL => 'all';
use strict;

my ($in_dir, $out_dir) = @ARGV;
my @files = <$in_dir/*.lua>;

foreach my $file (@files) {
    $file =~ /([^\/.]+)(.lua)$/;
    my $fname = "$1$2";
    my $varname = "rspamadm_script_$1";
    my $definename = uc $varname;

    open(IN, "< $file") or die "input missing";
    open(OUT, "> $out_dir/$fname.h") or die "output missing";

    print OUT <<EOD;
#ifndef ${definename}_GUARD_H
#define ${definename}_GUARD_H

static const char ${varname}\[\] = ""
EOD

    while (<IN>) {
        $_ =~ s/^(.*)$/"$1\\n"/;
        print OUT $_;
    }
    print OUT <<EOD;
"";
#endif
EOD
    close IN;
    close OUT;
}
