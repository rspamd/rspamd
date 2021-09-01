#!/usr/bin/env perl

use 5.010;
use Data::Dumper;
use Getopt::Long;
use Pod::Usage;
use Time::Local;
use IO::Handle;
use warnings;
use strict;

my @symbols_search;
my @symbols_exclude;
my @symbols_bidirectional;
my @symbols_groups;
my @symbols_ignored;
my %symbols_mult;
my %groups;
my $reject_score   = 15.0;
my $junk_score     = 6.0;
my $diff_alpha     = 0.1;
my $correlations   = 0;
my $nrelated       = 10;
my $log_file       = "";
my $search_pattern = "";
my $startTime      = "";
my $endTime;
my $num_logs;
my $exclude_logs = 0;
my $man          = 0;
my $json         = 0;
my $help         = 0;

# Associate file extensions with decompressors
my %decompressor = (
    'bz2' => 'bzip2 -cd',
    'gz'  => 'gzip -cd',
    'xz'  => 'xz -cd',
    'zst' => 'zstd -cd',
);

GetOptions(
    "reject-score|r=f"      => \$reject_score,
    "junk-score|j=f"        => \$junk_score,
    "symbol|s=s@"           => \@symbols_search,
    "symbol-bidir|S=s@"     => \@symbols_bidirectional,
    "exclude|X=s@"          => \@symbols_exclude,
    "ignore=s@"             => \@symbols_ignored,
    "group|g=s@"            => \@symbols_groups,
    "log|l=s"               => \$log_file,
    "mult=s"                => \%symbols_mult,
    "alpha-score|alpha|a=f" => \$diff_alpha,
    "correlations|c"        => \$correlations,
    "nrelated=i"            => \$nrelated,
    "search-pattern=s"      => \$search_pattern,
    "start=s"               => \$startTime,
    "end=s"                 => \$endTime,
    "num-logs|n=i"          => \$num_logs,
    "exclude-logs|x=i"      => \$exclude_logs,
    "json|j"                => \$json,
    "help|?"                => \$help,
    "man"                   => \$man
) or pod2usage(2);

pod2usage(1) if $help;
pod2usage( -exitval => 0, -verbose => 2 ) if $man;

# Global vars
my $total           = 0;
my $total_spam      = 0;
my $total_junk      = 0;
my $junk_symbols    = 0;
my $spam_symbols    = 0;
my $ham_symbols     = 0;
my $ham_spam_change = 0;
my $ham_junk_change = 0;
my %sym_res;
my $rspamd_log;
my $enabled             = 0;
my $log_file_num        = 1;
my $spinner_update_time = 0;

my %action;
my %timeStamp;
my %scanTime = (
    max   => 0,
    total => 0,
);
my %bidir_match;

foreach ( $startTime, $endTime ) { $_ = &normalized_time($_) }

# Convert bidirectional symbols
foreach my $s (@symbols_bidirectional) {
    $bidir_match{$s} = {
        spam => "${s}_SPAM",
        ham  => "${s}_HAM",
    };
    push @symbols_search, $s unless grep /^$s$/, @symbols_search;
}

# Deal with groups
my $group_id = 0;
foreach my $g (@symbols_groups) {
    my @symbols    = split /,/, $g;
    my $group_name = "group$group_id";

    foreach my $s (@symbols) {
        $groups{$s} = $group_name;
        push @symbols_search, $s unless grep /^$s$/, @symbols_search;
    }
}

@symbols_search = '.*'
  unless @symbols_search;

if ( $log_file eq '-' || $log_file eq '' ) {
    $rspamd_log = \*STDIN;
    &ProcessLog();
}
elsif ( -d "$log_file" ) {
    my $log_dir = "$log_file";

    my @logs = &GetLogfilesList($log_dir);

    # Process logs
    foreach (@logs) {
        my $ext = (/[^.]+\.?([^.]*?)$/)[0];
        my $dc  = $decompressor{$ext} || 'cat';

        open( $rspamd_log, "-|", "$dc $log_dir/$_" )
          or die "cannot execute $dc $log_dir/$_ : $!";

        printf { interactive(*STDERR) } "\033[J  Parsing log files: [%d/%d] %s\033[G", $log_file_num++, scalar @logs,
          $_;
        $spinner_update_time = 0;    # Force spinner update
        &spinner;

        &ProcessLog;

        close($rspamd_log)
          or warn "cannot close $dc $log_dir/$_: $!";
    }
    print { interactive(*STDERR) } "\033[J\033[G";    # Progress indicator clean-up
}
else {
    my $ext = ( $log_file =~ /[^.]+\.?([^.]*?)$/ )[0];
    my $dc  = $decompressor{$ext} || 'cat';
    open( $rspamd_log, "-|", "$dc $log_file" )
      or die "cannot execute $dc $log_file : $!";
    $spinner_update_time = 0;                         # Force spinner update
    &spinner;
    &ProcessLog();
}

my $total_ham = $total - ( $total_spam + $total_junk );

if ($json) {
    print "{";
    &Summary();
    print '"symbols":{';
    &SymbolsStat();
    print "}}\n";
}
else {
    &SymbolsStat();
    &Summary();
}

exit;

sub IsIgnored {
    my ($sym) = @_;

    foreach my $ex (@symbols_ignored) {
        if ( $sym =~ /^$ex$/ ) {
            return 1;
        }
    }

    return 0;
}

sub GenRelated {
    my ( $htb, $target_sym ) = @_;

    my @result;
    my $i = 0;
    foreach my $sym ( sort { $htb->{$b} <=> $htb->{$a} } keys %{$htb} ) {
        if ( $sym ne $target_sym ) {
            my @elt = ( $sym, $htb->{$sym} );
            push @result, \@elt;
            $i++;
        }

        last if $i > $nrelated;
    }

    return \@result;
}

sub StringifyRelated {
    my ( $ar, $total ) = @_;
    return
      join( "\n", ( map { sprintf "\t%s(%s: %.1f%%)", $_->[0], $_->[1], $_->[1] / ( $total * 1.0 ) * 100.0 } @{$ar} ) );
}

sub SymbolsStat {
    if ( $total > 0 ) {
        my $has_comma = 0;
        while ( my ( $s, $r ) = each(%sym_res) ) {
            if ( $r->{hits} > 0 ) {
                my $th = $r->{hits};
                my $sh = $r->{spam_hits};
                my $jh = $r->{junk_hits};
                my $hh = $r->{hits} - $sh - $jh;
                my ( $htp, $stp, $jtp );
                $htp = $hh * 100.0 / $total_ham  if $total_ham != 0;
                $stp = $sh * 100.0 / $total_spam if $total_spam != 0;
                $jtp = $jh * 100.0 / $total_junk if $total_junk != 0;

                if ($json) {
                    if ($has_comma) {
                        print ",";
                    }
                    else {
                        $has_comma = 1;
                    }
                    print "\"$s\":{";
                    JsonObjectElt( "avg_weight", $r->{'weight'}, "%.4f" );
                    print ",";
                    JsonObjectElt( "hits", $th, "%d" );
                    print ",";
                    JsonObjectElt( "hits_percentage", $th / $total, "%.4f" );
                    print ",";
                    JsonObjectElt( "spam_hits", $sh, "%d" );
                    print ",";
                    JsonObjectElt( "spam_to_total", $sh / $th, "%.4f" );
                    print ",";
                    JsonObjectElt( "spam_percentage", $stp / 100.0 || 0, "%.4f" );
                    print ",";
                    JsonObjectElt( "ham_hits", $hh, "%d" );
                    print ",";
                    JsonObjectElt( "ham_to_total", $hh / $th, "%.4f" );
                    print ",";
                    JsonObjectElt( "ham_percentage", $htp / 100.0 || 0, "%.4f" );
                    print ",";
                    JsonObjectElt( "junk_hits", $jh, "%d" );
                    print ",";
                    JsonObjectElt( "junk_to_total", $jh / $th, "%.4f" );
                    print ",";
                    JsonObjectElt( "junk_percentage", $jtp / 100.0 || 0, "%.4f" );
                }
                else {
                    printf "%s   avg. weight %.3f, hits %d(%.3f%%):
  Ham  %7.3f%%, %6d/%-6d (%7.3f%%)
  Spam %7.3f%%, %6d/%-6d (%7.3f%%)
  Junk %7.3f%%, %6d/%-6d (%7.3f%%)
", $s, $r->{weight} / $r->{hits}, $th, ( $th / $total * 100 ),
                      ( $hh / $th * 100 ), $hh, $total_ham,  ( $htp or 0 ),
                      ( $sh / $th * 100 ), $sh, $total_spam, ( $stp or 0 ),
                      ( $jh / $th * 100 ), $jh, $total_junk, ( $jtp or 0 );
                }
                my ( $schp, $jchp );
                $schp = $r->{spam_change} / $total_spam * 100.0 if $total_spam;
                $jchp = $r->{junk_change} / $total_junk * 100.0 if $total_junk;

                if ( $r->{weight} != 0 ) {
                    if ( !$json ) {
                        if ( $r->{weight} > 0 ) {
                            printf "
Spam changes (ham/junk -> spam): %6d/%-6d (%7.3f%%)
Spam  changes / total spam hits: %6d/%-6d (%7.3f%%)
Junk changes      (ham -> junk): %6d/%-6d (%7.3f%%)
Junk  changes / total junk hits: %6d/%-6d (%7.3f%%)
",
                              $r->{spam_change}, $th,         ( $r->{spam_change} / $th * 100 ),
                              $r->{spam_change}, $total_spam, ( $schp or 0 ),
                              $r->{junk_change}, $th,         ( $r->{junk_change} / $th * 100 ),
                              $r->{junk_change}, $total_junk, ( $jchp or 0 );
                        }
                        else {
                            printf "
Spam changes (spam -> junk/ham): %6d/%-6d (%7.3f%%)
Spam changes / total spam hits : %6d/%-6d (%7.3f%%)
Junk changes (junk -> ham)     : %6d/%-6d (%7.3f%%)
Junk changes / total junk hits : %6d/%-6d (%7.3f%%)
",
                              $r->{spam_change}, $th,         ( $r->{spam_change} / $th * 100 ),
                              $r->{spam_change}, $total_spam, ( $schp or 0 ),
                              $r->{junk_change}, $th,         ( $r->{junk_change} / $th * 100 ),
                              $r->{junk_change}, $total_junk, ( $jchp or 0 );
                        }
                    }
                    else {
                        print ",";
                        JsonObjectElt( "spam_change", $r->{spam_change}, "%.4f" );
                        print ",";
                        JsonObjectElt( "junk_change", $r->{junk_change}, "%.4f" );
                    }
                }

                if ($correlations) {

                    my $spam_related = GenRelated( $r->{symbols_met_spam}, $s );
                    my $junk_related = GenRelated( $r->{symbols_met_junk}, $s );
                    my $ham_related  = GenRelated( $r->{symbols_met_ham},  $s );

                    if ( !$json ) {
                        print "Correlations report:\n";

                        while ( my ( $cs, $hits ) = each %{ $r->{corr} } ) {
                            my $corr_prob   = $r->{'hits'} / $total;
                            my $merged_hits = 0;
                            if ( $r->{symbols_met_spam}->{$cs} ) {
                                $merged_hits += $r->{symbols_met_spam}->{$cs};
                            }
                            if ( $r->{symbols_met_junk}->{$cs} ) {
                                $merged_hits += $r->{symbols_met_junk}->{$cs};
                            }
                            if ( $r->{symbols_met_ham}->{$cs} ) {
                                $merged_hits += $r->{symbols_met_ham}->{$cs};
                            }

                            if ( $merged_hits > 0 ) {
                                printf "Probability of %s when %s fires: %.3f\n", $cs, $s,
                                  ( ( $merged_hits / $total ) / $corr_prob );
                            }
                        }

                        print "Related symbols report:\n";
                        printf "Top related in spam:\n %s\n", StringifyRelated( $spam_related, $r->{spam_hits} );
                        printf "Top related in junk:\n %s\n", StringifyRelated( $junk_related, $r->{junk_hits} );
                        printf "Top related in ham:\n %s\n",
                          StringifyRelated( $ham_related, $r->{hits} - $r->{spam_hits} - $r->{junk_hits} );
                    }
                    else {
                        print ",";
                        print "\"correllations\":{";

                        my $has_comma_ = 0;
                        while ( my ( $cs, $hits ) = each %{ $r->{corr} } ) {
                            if ($has_comma_) {
                                print ",";
                            }
                            else {
                                $has_comma_ = 1;
                            }
                            my $corr_prob = $hits / $total;
                            my $sym_prob  = $r->{hits} / $total;
                            JsonObjectElt( $cs, ( $corr_prob / $sym_prob ), "%.4f" );
                        }

                        print "}";
                    }
                }

                print "}" if $json;
            }
            else {
                print "Symbol $s has not been met\n" if !$json;
            }

            print '-' x 80 . "\n" if !$json;
        }
    }
}

sub Summary() {
    if ( !$json ) {
        print "
=== Summary ", '=' x 68, "
Messages scanned: $total";
        printf " [ %s / %s ]
", $timeStamp{'start'}, $timeStamp{'end'}
          if defined $timeStamp{'start'};
        say '';
        printf "%11s: %6.2f%%, %d\n", $_, 100 * $action{$_} / $total, $action{$_} for sort keys %action;
        say '';
        printf "scan time min/avg/max = %.2f/%.2f/%.2f s
", $scanTime{'min'} / 1000, ($total) ? $scanTime{'total'} / $total / 1000 : undef, $scanTime{'max'} / 1000
          if exists $scanTime{'min'};
        say '=' x 80;
    }
    else {
        JsonObjectElt( "total", $total, "%d" );
        print ",";

        if ( defined $timeStamp{'start'} ) {
            JsonObjectElt( "start", $timeStamp{'start'} );
            print ",";
        }

        if ( defined $timeStamp{'end'} ) {
            JsonObjectElt( "end", $timeStamp{'end'} );
            print ",";
        }

        print "\"actions\":{";

        my $has_comma = 0;
        foreach my $a ( sort keys %action ) {
            if ($has_comma) {
                print ",";
            }
            else {
                $has_comma = 1;
            }
            JsonObjectElt( $a, $action{$a}, "%d" );
        }
        print "},";
    }
}

sub ProcessRelated {
    my ( $symbols, $target, $source ) = @_;

    foreach my $s ( @{$symbols} ) {
        $s =~ /^([^\(]+)(\(([^\)]+)\))?/;
        my $sym_name  = $1;
        my $sym_score = 0;

        if ( $groups{$sym_name} ) {
            $sym_name = $groups{$sym_name};
        }

        next if ( $source eq $sym_name );

        next if IsIgnored($sym_name);

        if ($2) {
            $sym_score = $3 * ($symbols_mult{$sym_name} or 1.0);

            if ( abs($sym_score) < $diff_alpha ) {
                next;
            }

            my $bm = $bidir_match{$sym_name};
            if ($bm) {
                if ( $sym_score >= 0 ) {
                    $sym_name = $bm->{'spam'};
                }
                else {
                    $sym_name = $bm->{'ham'};
                }
            }
        }

        if ( exists( $target->{$sym_name} ) ) {
            $target->{$sym_name}++;
        }
        else {
            $target->{$sym_name} = 1;
        }
    }
}

sub ProcessLog {
    my ( $ts_format, @line ) = &log_time_format($rspamd_log);

    while () {
        last if eof $rspamd_log;
        $_ = (@line) ? shift @line : <$rspamd_log>;

        if ( !$enabled && ( $search_pattern eq "" || /$search_pattern/ ) ) {
            $enabled = 1;
        }

        next if !$enabled;

        if (/^.*rspamd_task_write_log.*$/) {
            &spinner;
            my $ts;
            if ( $ts_format eq 'syslog' ) {
                $ts = syslog2iso( join ' ', ( split /\s+/ )[ 0 .. 2 ] );
            }
            elsif ( $ts_format eq 'syslog5424' ) {
                /^([0-9-]+)T([0-9:]+)/;
                $ts = "$1 $2";
            }
            else {
                $ts = join ' ', ( split /\s+/ )[ 0 .. 1 ];
            }

            next if ( $ts lt $startTime );
            next if ( defined $endTime && $ts gt $endTime );

            if ( $_ !~
                /\(([^()]+)\): \[(NaN|-?\d+(?:\.\d+)?)\/(-?\d+(?:\.\d+)?)\]\s+\[([^\]]+)\].+? time: (\d+\.\d+)ms/ )
            {
                #print "BAD: $_\n";
                next;
            }

            my @symbols   = split /(?:\{[^}]*\})?(?:$|,)/, $4;
            my $scan_time = $5;
            my $act       = $1;
            my $score     = $2 * 1.0;
            my $skip      = 0;

            foreach my $ex (@symbols_exclude) {
                my @found = grep { /^$ex/ } @symbols;

                if ( scalar(@found) > 0 ) {
                    $skip = 1;
                    last;
                }
            }

            next if ( $skip != 0 );

            if ( defined( $timeStamp{'end'} ) ) {
                $timeStamp{'end'} = $ts if ( $ts gt $timeStamp{'end'} );
            }
            else {
                $timeStamp{'end'} = $ts;
            }

            if ( defined( $timeStamp{'start'} ) ) {
                $timeStamp{'start'} = $ts if ( $ts lt $timeStamp{'start'} );
            }
            else {
                $timeStamp{'start'} = $ts;
            }

            $scanTime{'min'} = $scan_time if ( !exists $scanTime{'min'} || $scanTime{'min'} > $scan_time );
            $scanTime{'max'} = $scan_time if ( $scanTime{'max'} < $scan_time );
            $scanTime{'total'} += $scan_time;

            $action{$act}++;
            $total++;

            if ( $score >= $reject_score ) {
                $total_spam++;
            }
            elsif ( $score >= $junk_score ) {
                $total_junk++;
            }

            my @sym_names;

            foreach my $s (@symbols_search) {
                my @selected = grep /$s/, @symbols;

                if ( scalar(@selected) > 0 ) {

                    foreach my $sym (@selected) {
                        $sym =~ /^([^\(]+)(\(([^\)]+)\))?/;
                        my $sym_name  = $1;
                        my $sym_score = 0;
                        my $orig_name = $sym_name;

                        if ($2) {
                            $sym_score = $3 * ($symbols_mult{$sym_name} or 1.0);

                            if ( abs($sym_score) < $diff_alpha ) {
                                next;
                            }

                            my $bm = $bidir_match{$sym_name};
                            if ($bm) {
                                if ( $sym_score >= 0 ) {
                                    $sym_name = $bm->{'spam'};
                                }
                                else {
                                    $sym_name = $bm->{'ham'};
                                }
                            }
                        }

                        next if $orig_name !~ /^$s/;

                        if ( $groups{$s} ) {

                            # Replace with group
                            $sym_name = $groups{$s};
                        }

                        push @sym_names, $sym_name;

                        if ( !$sym_res{$sym_name} ) {
                            $sym_res{$sym_name} = {
                                hits             => 0,
                                spam_hits        => 0,
                                junk_hits        => 0,
                                spam_change      => 0,
                                junk_change      => 0,
                                weight           => 0,
                                corr             => {},
                                symbols_met_spam => {},
                                symbols_met_ham  => {},
                                symbols_met_junk => {},
                            };
                        }

                        my $r = $sym_res{$sym_name};

                        $r->{hits}++;
                        $r->{weight} += $sym_score;
                        my $is_spam = 0;
                        my $is_junk = 0;

                        if ( $score >= $reject_score ) {
                            $is_spam = 1;
                            $r->{spam_hits}++;
                            if ($correlations) {
                                ProcessRelated( \@symbols, $r->{symbols_met_spam}, $sym_name );
                            }
                        }
                        elsif ( $score >= $junk_score ) {
                            $is_junk = 1;
                            $r->{junk_hits}++;
                            if ($correlations) {
                                ProcessRelated( \@symbols, $r->{symbols_met_junk}, $sym_name );
                            }
                        }
                        else {
                            if ($correlations) {
                                ProcessRelated( \@symbols, $r->{symbols_met_ham}, $sym_name );
                            }
                        }

                        if ( $sym_score != 0 ) {
                            my $score_without = $score - $sym_score;

                            if ( $sym_score > 0 ) {
                                if ( $is_spam && $score_without < $reject_score ) {
                                    $r->{spam_change}++;
                                }
                                if ( $is_junk && $score_without < $junk_score ) {
                                    $r->{junk_change}++;
                                }
                            }
                            else {
                                if ( !$is_spam && $score_without >= $reject_score ) {
                                    $r->{spam_change}++;
                                }
                                if ( !$is_junk && $score_without >= $junk_score ) {
                                    $r->{junk_change}++;
                                }
                            }
                        }
                    }    # End foreach symbols selected
                }
            }

            if ($correlations) {
                foreach my $sym (@sym_names) {
                    next if IsIgnored($sym);
                    my $r = $sym_res{$sym};

                    foreach my $corr_sym (@sym_names) {
                        if ( $corr_sym ne $sym ) {
                            if ( $r->{'corr'}->{$corr_sym} ) {
                                $r->{'corr'}->{$corr_sym}++;
                            }
                            else {
                                $r->{'corr'}->{$corr_sym} = 1;
                            }
                        }
                    }
                }    # End of correlations check
            }
        }
    }
}

sub JsonObjectElt() {
    my ( $k, $v ) = @_;
    my $f = defined $_[2] ? $_[2] : '%s';

    if ( $f eq "%s" ) {
        $f = "\"%s\"";
    }

    printf "\"%s\":$f", $k, $v;
}

sub GetLogfilesList {
    my ($dir) = @_;
    opendir( DIR, $dir ) or die $!;

    my $pattern = join( '|', keys %decompressor );
    my $re      = qr/\.[0-9]+(?:\.(?:$pattern))?/;

    # Add unnumbered logs first
    my @logs =
      grep { -f "$dir/$_" && !/$re/ } readdir(DIR);

    # Add numbered logs
    rewinddir(DIR);
    push( @logs, ( sort numeric ( grep { -f "$dir/$_" && /$re/ } readdir(DIR) ) ) );

    closedir(DIR);

    # Select required logs and revers their order
    @logs =
      reverse splice( @logs, $exclude_logs, $num_logs ||= @logs - $exclude_logs );

    # Loop through array printing out filenames
    print { interactive(*STDERR) } "\nLog files to process:\n";
    foreach my $file (@logs) {
        print { interactive(*STDERR) } "  $file\n";
    }
    print { interactive(*STDERR) } "\n";

    return @logs;
}

sub log_time_format {
    my $fh = shift;
    my ( $format, $line );
    while (<$fh>) {
        $line = $_;

        # 2017-08-08 00:00:01 #66984(
        # 2017-08-08 00:00:01.001 #66984(
        if (/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(\.\d{3,5})? #\d+\(/) {
            $format = 'rspamd';
            last;
        }

        # Aug  8 00:02:50 #66986(
        elsif (/^\w{3} (?:\s?\d|\d\d) \d\d:\d\d:\d\d #\d+\(/) {
            $format = 'syslog';
            last;
        }

        # Aug  8 00:02:50 hostname rspamd[66986]
        elsif (/^\w{3} (?:\s?\d|\d\d) \d\d:\d\d:\d\d \S+ rspamd\[\d+\]/) {
            $format = 'syslog';
            last;
        }

        # 2018-04-16T06:25:46.012590+02:00 rspamd rspamd[12968]
        elsif (/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[-+]\d{2}:\d{2}) \S+ rspamd\[\d+\]/) {
            $format = 'syslog5424';
            last;
        }

        # Skip newsyslog messages
        # Aug  8 00:00:00 hostname newsyslog[63284]: logfile turned over
        elsif (/^\w{3} (?:\s?\d|\d\d) \d\d:\d\d:\d\d\ \S+ newsyslog\[\d+\]: logfile turned over$/) {
            next;
        }

        # Skip journalctl messages
        # -- Logs begin at Mon 2018-01-15 11:16:24 MSK, end at Fri 2018-04-27 09:10:30 MSK. --
        elsif (
/^-- Logs begin at \w{3} \d{4}-\d\d-\d\d \d\d:\d\d:\d\d [A-Z]{3}, end at \w{3} \d{4}-\d\d-\d\d \d\d:\d\d:\d\d [A-Z]{3}\. --$/
          )
        {
            next;
        }
        else {
            print "Unknown log format\n";
            exit 1;
        }
    }
    return ( $format, $line );
}

sub normalized_time {
    return
      if !defined( $_ = shift );

    /^\d\d(?::\d\d){0,2}$/
      ? sprintf '%04d-%02d-%02d %s', 1900 + (localtime)[5], 1 + (localtime)[4], (localtime)[3], $_
      : $_;
}

sub numeric {
    $a =~ /\.(\d+)\./;
    my $a_num = $1;
    $b =~ /\.(\d+)\./;
    my $b_num = $1;

    $a_num <=> $b_num;
}

sub spinner {
    my @spinner = qw{/ - \ |};
    return
      if ( ( time - $spinner_update_time ) < 1 );
    $spinner_update_time = time;
    printf { interactive(*STDERR) } "%s\r", $spinner[ $spinner_update_time % @spinner ];
    select()->flush();
}

# Convert syslog timestamp to "ISO 8601 like" format
# using current year as syslog does not record the year (nor the timezone)
# or the last year if the guessed time is in the future.
sub syslog2iso {
    my %month_map;
    @month_map{qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)} = 0 .. 11;

    my ( $month, @t ) = $_[0] =~ m/^(\w{3}) \s\s? (\d\d?) \s (\d\d):(\d\d):(\d\d)/x;
    my $epoch =
      timelocal( ( reverse @t ), $month_map{$month}, 1900 + (localtime)[5] );
    sprintf '%04d-%02d-%02d %02d:%02d:%02d', 1900 + (localtime)[5] - ( $epoch > time ), $month_map{$month} + 1, @t;
}

### Imported from IO::Interactive 1.022 Perl module
sub is_interactive {
    ## no critic (ProhibitInteractiveTest)

    my ($out_handle) = ( @_, select );    # Default to default output handle

    # Not interactive if output is not to terminal...
    return 0 if not -t $out_handle;

    # If *ARGV is opened, we're interactive if...
    if ( tied(*ARGV) or defined( fileno(ARGV) ) ) {    # this is what 'Scalar::Util::openhandle *ARGV' boils down to

        # ...it's currently opened to the magic '-' file
        return -t *STDIN if defined $ARGV && $ARGV eq '-';

        # ...it's at end-of-file and the next file is the magic '-' file
        return @ARGV > 0 && $ARGV[0] eq '-' && -t *STDIN if eof *ARGV;

        # ...it's directly attached to the terminal
        return -t *ARGV;
    }

    # If *ARGV isn't opened, it will be interactive if *STDIN is attached
    # to a terminal.
    else {
        return -t *STDIN;
    }
}

### Imported from IO::Interactive 1.022 Perl module
local ( *DEV_NULL, *DEV_NULL2 );
my $dev_null;

BEGIN {
    pipe *DEV_NULL, *DEV_NULL2
      or die "Internal error: can't create null filehandle";
    $dev_null = \*DEV_NULL;
}

### Imported from IO::Interactive 1.022 Perl module
sub interactive {
    my ($out_handle) = ( @_, \*STDOUT );    # Default to STDOUT
    return &is_interactive ? $out_handle : $dev_null;
}

__END__

=head1 NAME

rspamd_stats - analyze Rspamd rules by parsing log files

=head1 SYNOPSIS

rspamd_stats [options] [--symbol=SYM1 [--symbol=SYM2...]] [--log file]

 Options:
   --log=file             log file or directory to read (stdin by default)
   --reject-score=score   set reject threshold (15 by default)
   --junk-score=score     set junk score (6.0 by default)
   --symbol=sym           check specified symbol (perl regexps, '.*' by default)
   --alpha-score=score    set ignore score for symbols (0.1 by default)
   --correlations         enable correlations report
   --nrelated=integer     show that amount of related symbols (10 by default)
   --search-pattern       do not process input unless the desired pattern is found
   --start                starting time (oldest) for log parsing
   --end                  ending time (newest) for log parsing
   --num-logs=integer     number of recent logfiles to analyze (all files in the directory by default)
   --exclude-logs=integer number of latest logs to exclude (0 by default)
   --json                 print json output instead of human readable
   --help                 brief help message
   --mult=sym=number      multiply symbol score
   --man                  full documentation

=head1 OPTIONS

=over 8

=item B<--log>

Specifies log file or directory to read data from. If a directory is specified B<rspamd_stats> analyses files in the
directory including known compressed file types. Number of log files can be limited using B<--num-logs> and
B<--exclude-logs> options. This assumes that files in the log directory have B<newsyslog(8)>- or B<logrotate(8)>-like
name format with numeric indexes. Files without indexes (generally it is merely one file) are considered the most
recent and files with lower indexes are considered newer.

=item B<--reject-score>

Specifies the reject (spam) threshold.

=item B<--junk-score>

Specifies the junk (add header or rewrite subject) threshold.

=item B<--alpha-score>

Specifies the minimum score for a symbol to be considered by this script.

=item B<--symbol>

Add symbol or pattern (pcre format) to analyze.

=item B<--num-logs>

If set, limits number of analyzed logfiles in the directory to the specified value.

=item B<--exclude-logs>

Number of latest logs to exclude (0 by default).

=item B<--correlations>

Additionally print correlation rate for each symbol displayed. This routine calculates merely paired correlations
between symbols.

=item B<--search-pattern>

Do not process input unless finding the specified regular expression. Useful to skip logs to a certain position.

=item  B<--exclude>

Exclude log lines if certain symbols are fired (e.g. GTUBE). You may specify this option multiple time to skip multiple
symbols.

=item B<--start>

Select log entries after this time. Format: C<YYYY-MM-DD HH:MM:SS> (can be truncated to any desired accuracy). If used
with B<--end> select entries between B<--start> and B<--end>. The omitted date defaults to the current date if you
supply the time.

=item B<--end>

Select log entries before this time. Format: C<YYYY-MM-DD HH:MM:SS> (can be truncated to any desired accuracy). If used
with B<--start> select entries between B<--start> and B<--end>. The omitted date defaults to the current date if you
supply the time.

=item B<--mult=symbol=number>

Multiplies score for the named symbol by the provided multiplier.

=item B<--help>

Print a brief help message and exits.

=item B<--man>

Prints the manual page and exits.

=back

=head1 DESCRIPTION

B<rspamd_stats> will read the given log file (or standard input) and provide statistics for the specified symbols:

    Symbol: BAYES_SPAM (weight 3.763) (381985 hits, 26.827%)
    Ham hits: 184557 (48.315%), total ham: 1095487 (ham with BAYES_SPAM: 16.847%)
    Spam hits: 15134 (3.962%), total spam: 16688 (spam with BAYES_SPAM: 90.688%)
    Junk hits: 182294 (47.723%), total junk: 311699 (junk with BAYES_SPAM: 58.484%)
    Spam changes (ham/junk -> spam): 7026 (1.839%), total percentage (changes / spam hits): 42.102%
    Junk changes (ham -> junk): 95192 (24.920%), total percentage (changes / junk hits): 30.540%

Where there are the following attributes:

=over 4

=item *

B<Weight>: average score for a symbols

=item *

B<Total hits>: total number of hits and percentage of symbol hits divided by total number of messages

=item *

B<HAM hits>: provides the following information about B<HAM> messages with the specified symbol (from left to right):

=over 4

=item 1.

B<total symbol hits>: number of messages that has this symbol and are B<HAM>

=item 2.

B<ham percentage>: number of symbol hits divided by overall B<HAM> messages count

=item 3.

B<total ham hits>: overall number of B<HAM> messages

=item 4.

B<ham with symbol percentage>: percentage of number of hits with specified symbol in B<HAM> messages divided by total
number of B<HAM> messages.

=back

=item *

B<SPAM hits>: provides the following information about B<SPAM> messages - same as previous but for B<SPAM> class.

=item *

B<Junk hits>: provides the following information about B<Junk> messages - same as previous but for B<JUNK> class.

=item *

B<Spam changes>: displays data about how much messages switched their class because of the specific symbol weight.

=item *

B<Junk changes>: displays data about how much messages switched their class because of the specific symbol weight.

=back

=cut
