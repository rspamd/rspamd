#!/usr/bin/env perl

use strict;
use warnings;
use utf8;

# Parse ASAN log and group leaks by stack trace
sub parse_asan_log {
    my ($fh) = @_;
    my %leaks;

    while (my $line = <$fh>) {
        # Match leak header: "Indirect leak of 30 byte(s) in 2 object(s) allocated from:"
        if ($line =~ /^(Indirect|Direct) leak of (\d+) byte\(s\) in (\d+) object\(s\) allocated from:/) {
            my $leak_type = $1;
            my $bytes_leaked = $2;
            my $objects_count = $3;

            # Read stack trace
            my @trace;
            while (my $trace_line = <$fh>) {
                chomp $trace_line;
                $trace_line =~ s/^\s+|\s+$//g;

                # Stack trace lines start with #N
                if ($trace_line =~ /^\s*#\d+/) {
                    push @trace, $trace_line;
                }
                else {
                    # End of trace
                    last;
                }
            }

            # Use trace as key for grouping
            my $trace_key = join("\n", @trace);

            if (!exists $leaks{$trace_key}) {
                $leaks{$trace_key} = {
                    bytes => 0,
                    objects => 0,
                    trace => \@trace,
                    type => $leak_type
                };
            }

            $leaks{$trace_key}{bytes} += $bytes_leaked;
            $leaks{$trace_key}{objects} += $objects_count;
        }
    }

    return \%leaks;
}

# Print leaks sorted by bytes leaked
sub print_leaks_sorted {
    my ($leaks) = @_;

    # Sort by bytes leaked (descending)
    my @sorted_leaks = sort { $leaks->{$b}{bytes} <=> $leaks->{$a}{bytes} } keys %$leaks;

    my $total_bytes = 0;
    my $total_objects = 0;

    print "=" x 80 . "\n";
    print "ASAN Leak Analysis - Sorted by bytes leaked\n";
    print "=" x 80 . "\n";
    print "\n";

    my $idx = 1;
    foreach my $trace_key (@sorted_leaks) {
        my $leak = $leaks->{$trace_key};
        $total_bytes += $leak->{bytes};
        $total_objects += $leak->{objects};

        print "Leak #$idx: $leak->{type} leak of $leak->{bytes} byte(s) in $leak->{objects} object(s) allocated from:\n";
        foreach my $trace_line (@{$leak->{trace}}) {
            print "    $trace_line\n";
        }
        print "\n";
        $idx++;
    }

    my $unique_traces = scalar @sorted_leaks;
    print "=" x 80 . "\n";
    print "Total: $total_bytes bytes leaked in $total_objects objects across $unique_traces unique stack traces\n";
    print "=" x 80 . "\n";
}

# Main
sub main {
    if (@ARGV < 1) {
        print STDERR "Usage: $0 <asan_log_file>\n";
        print STDERR "       $0 -     (read from stdin)\n";
        print STDERR "       command 2>&1 | $0 -\n";
        print STDERR "\n";
        print STDERR "Example:\n";
        print STDERR "  $0 /tmp/asan.log\n";
        print STDERR "  rspamadm configdump 2>&1 | $0 -\n";
        exit 1;
    }

    my $log_file = $ARGV[0];
    my $fh;

    if ($log_file eq "-") {
        # Read from stdin
        $fh = \*STDIN;
        binmode($fh, ":bytes");
    }
    else {
        # Read from file
        if (!open($fh, "<:bytes", $log_file)) {
            print STDERR "Error: Cannot open file '$log_file': $!\n";
            exit 1;
        }
    }

    my $leaks = parse_asan_log($fh);

    if ($log_file ne "-") {
        close($fh);
    }

    print_leaks_sorted($leaks);
}

main();
