#!/usr/bin/env perl

use warnings;
use strict;
use Pod::Usage;
use Getopt::Long;
use Time::HiRes qw(gettimeofday tv_interval);
use JSON::XS;
use String::ShellQuote;
use FileHandle;
use IPC::Open2;
use Data::Dumper;

my $spam_dir;
my $ham_dir;
my $parallel            = 1;
my $classifier          = "bayes";
my $spam_symbol         = "BAYES_SPAM";
my $ham_symbol          = "BAYES_HAM";
my $timeout             = 10;
my $rspamc              = $ENV{'RSPAMC'} || "rspamc";
my $bogofilter          = $ENV{'BOGOFILTER'} || "bogofilter";
my $dspam               = $ENV{'DSPAM'} || "dspam";
my $train_fraction      = 0.5;
my $use_bogofilter      = 0;
my $use_dspam           = 0;
my $check_only          = 0;
my $rspamc_prob_trigger = 95;
my $man;
my $help;

GetOptions(
    "spam|s=s"           => \$spam_dir,
    "ham|h=s"            => \$ham_dir,
    "spam-symbol=s"      => \$spam_symbol,
    "ham-symbol=s"       => \$ham_symbol,
    "classifier|c=s"     => \$classifier,
    "timeout|t=f"        => \$timeout,
    "parallel|p=i"       => \$parallel,
    "train-fraction|t=f" => \$train_fraction,
    "bogofilter|b"       => \$use_bogofilter,
    "dspam|d"            => \$use_dspam,
    "check-only"         => \$check_only,
    "help|?"             => \$help,
    "man"                => \$man
) or pod2usage(2);

pod2usage(1) if $help;
pod2usage( -exitval => 0, -verbose => 2 ) if $man;

sub read_dir_files {
    my ( $dir, $target ) = @_;
    opendir( my $dh, $dir ) or die "cannot open dir $dir: $!";
    while ( my $file = readdir $dh ) {
        if ( -f "$dir/$file" ) {
            push @{$target}, "$dir/$file";
        }
    }
}

sub shuffle_array {
    my ($ar) = @_;

    for ( my $i = 0 ; $i < scalar @{$ar} ; $i++ ) {
        if ( $i > 1 ) {
            my $sel = int( rand( $i - 1 ) );
            ( @{$ar}[$i], @{$ar}[$sel] ) = ( @{$ar}[$sel], @{$ar}[$i] );
        }
    }
}

sub learn_rspamc {
    my ( $files, $spam ) = @_;
    my $processed = 0;

    my $cmd         = $spam ? "learn_spam" : "learn_ham";
    my $args_quoted = shell_quote @{$files};
    open( my $p, "$rspamc -t $timeout -c $classifier --compact -j -n $parallel $cmd $args_quoted |" )
      or die "cannot spawn $rspamc: $!";

    while (<$p>) {
        my $res = eval('decode_json($_)');
        if ( $res && $res->{'success'} ) {
            $processed++;
        }
    }

    return $processed;
}

sub learn_bogofilter {
    my ( $files, $spam ) = @_;
    my $processed = 0;

    foreach my $f ( @{$files} ) {
        my $args_quoted = shell_quote $f;
        my $fl          = $spam ? "-s" : "-n";
        `$bogofilter  -I $args_quoted $fl`;
        if ( $? == 0 ) {
            $processed++;
        }
    }

    return $processed;
}

sub learn_dspam {
    my ( $files, $spam ) = @_;
    my $processed = 0;

    foreach my $f ( @{$files} ) {
        my $args_quoted = shell_quote $f;
        my $fl          = $spam ? "--class=spam" : "--class=innocent";
        open( my $p, "|$dspam --user nobody --source=corpus --stdout --mode=toe $fl" )
          or die "cannot run $dspam: $!";

        open( my $inp, "< $f" );
        while (<$inp>) {
            print $p $_;
        }
    }

    return $processed;
}

sub learn_samples {
    my ( $ar_ham, $ar_spam ) = @_;
    my $len;
    my $processed = 0;
    my $total     = 0;
    my $learn_func;

    my @files_spam;
    my @files_ham;

    if ($use_dspam) {
        $learn_func = \&learn_dspam;
    }
    elsif ($use_bogofilter) {
        $learn_func = \&learn_bogofilter;
    }
    else {
        $learn_func = \&learn_rspamc;
    }

    $len = int( scalar @{$ar_ham} * $train_fraction );
    my @cur_vec;

    # Shuffle spam and ham samples
    for ( my $i = 0 ; $i < $len ; $i++ ) {
        if ( $i > 0 && ( $i % $parallel == 0 || $i == $len - 1 ) ) {
            push @cur_vec, @{$ar_ham}[$i];
            push @files_ham, [@cur_vec];
            @cur_vec = ();
            $total++;
        }
        else {
            push @cur_vec, @{$ar_ham}[$i];
        }
    }

    $len     = int( scalar @{$ar_spam} * $train_fraction );
    @cur_vec = ();
    for ( my $i = 0 ; $i < $len ; $i++ ) {
        if ( $i > 0 && ( $i % $parallel == 0 || $i == $len - 1 ) ) {
            push @cur_vec, @{$ar_spam}[$i];
            push @files_spam, [@cur_vec];
            @cur_vec = ();
            $total++;
        }
        else {
            push @cur_vec, @{$ar_spam}[$i];
        }
    }

    for ( my $i = 0 ; $i < $total ; $i++ ) {
        my $args;
        my $spam;

        if ( $i % 2 == 0 ) {
            $args = pop @files_spam;

            if ( !$args ) {
                $args = pop @files_ham;
                $spam = 0;
            }
            else {
                $spam = 1;
            }
        }
        else {
            $args = pop @files_ham;
            if ( !$args ) {
                $args = pop @files_spam;
                $spam = 1;
            }
            else {
                $spam = 0;
            }
        }

        my $r = $learn_func->( $args, $spam );
        if ($r) {
            $processed += $r;
        }
    }

    return $processed;
}

sub check_rspamc {
    my ( $files, $spam, $fp_cnt, $fn_cnt, $detected_cnt ) = @_;

    my $args_quoted = shell_quote @{$files};
    my $processed   = 0;

    open(
        my $p,
"$rspamc -t $timeout -n $parallel --header=\"Settings: {symbols_enabled=[BAYES_SPAM]}\" --compact -j $args_quoted |"
    ) or die "cannot spawn $rspamc: $!";

    while (<$p>) {
        my $res = eval('decode_json($_)');
        if ( $res && $res->{'default'} ) {
            $processed++;

            if ($spam) {
                if ( $res->{'default'}->{$ham_symbol} ) {
                    my $m = $res->{'default'}->{$ham_symbol}->{'options'}->[0];
                    if ( $m && $m =~ /^(\d+(?:\.\d+)?)%$/ ) {
                        my $percentage = int($1);
                        if ( $percentage >= $rspamc_prob_trigger ) {
                            $$fp_cnt++;
                        }
                    }
                    else {
                        $$fp_cnt++;
                    }
                }
                elsif ( !$res->{'default'}->{$spam_symbol} ) {
                    $$fn_cnt++;
                }
                else {
                    $$detected_cnt++;
                }
            }
            else {
                if ( $res->{'default'}->{$spam_symbol} ) {
                    my $m = $res->{'default'}->{$spam_symbol}->{'options'}->[0];
                    if ( $m && $m =~ /^(\d+(?:\.\d+)?)%$/ ) {

                        my $percentage = int($1);
                        if ( $percentage >= $rspamc_prob_trigger ) {
                            $$fp_cnt++;
                        }
                    }
                    else {
                        $$fp_cnt++;
                    }
                }
                elsif ( !$res->{'default'}->{$ham_symbol} ) {
                    $$fn_cnt++;
                }
                else {
                    $$detected_cnt++;
                }
            }
        }
    }

    return $processed;
}

sub check_bogofilter {
    my ( $files, $spam, $fp_cnt, $fn_cnt, $detected_cnt ) = @_;
    my $processed = 0;

    foreach my $f ( @{$files} ) {
        my $args_quoted = shell_quote $f;

        open( my $p, "$bogofilter -t -I $args_quoted |" )
          or die "cannot spawn $bogofilter: $!";

        while (<$p>) {
            if ( $_ =~ /^([SHU])\s+.*$/ ) {
                $processed++;

                if ($spam) {
                    if ( $1 eq 'H' ) {
                        $$fp_cnt++;
                    }
                    elsif ( $1 eq 'U' ) {
                        $$fn_cnt++;
                    }
                    else {
                        $$detected_cnt++;
                    }
                }
                else {
                    if ( $1 eq 'S' ) {
                        $$fp_cnt++;
                    }
                    elsif ( $1 eq 'U' ) {
                        $$fn_cnt++;
                    }
                    else {
                        $$detected_cnt++;
                    }
                }
            }
        }
    }

    return $processed;
}

sub check_dspam {
    my ( $files, $spam, $fp_cnt, $fn_cnt, $detected_cnt ) = @_;
    my $processed = 0;

    foreach my $f ( @{$files} ) {
        my $args_quoted = shell_quote $f;

        my $pid = open2( *Reader, *Writer, "$dspam --user nobody --classify --stdout --mode=notrain" );
        open( my $inp, "< $f" );
        while (<$inp>) {
            print Writer $_;
        }
        close Writer;

        while (<Reader>) {
            if ( $_ =~ qr(^X-DSPAM-Result: nobody; result="([^"]+)"; class="[^"]+"; probability=(\d+(?:\.\d+)?).*$) ) {
                $processed++;
                my $percentage = int( $2 * 100.0 );

                if ($spam) {
                    if ( $1 eq 'Innocent' ) {
                        if ( $percentage <= ( 100 - $rspamc_prob_trigger ) ) {
                            $$fp_cnt++;
                        }
                    }
                    elsif ( $1 ne 'Spam' ) {
                        $$fn_cnt++;
                    }
                    else {
                        $$detected_cnt++;
                    }
                }
                else {
                    if ( $1 eq 'Spam' ) {
                        if ( $percentage >= $rspamc_prob_trigger ) {
                            $$fp_cnt++;
                        }
                    }
                    elsif ( $1 ne 'Innocent' ) {
                        $$fn_cnt++;
                    }
                    else {
                        $$detected_cnt++;
                    }
                }
            }
        }
        close Reader;
        waitpid( $pid, 0 );
    }

    return $processed;
}

sub cross_validate {
    my ($hr)          = @_;
    my $args          = "";
    my $processed     = 0;
    my $fp_spam       = 0;
    my $fn_spam       = 0;
    my $fp_ham        = 0;
    my $fn_ham        = 0;
    my $total_spam    = 0;
    my $total_ham     = 0;
    my $detected_spam = 0;
    my $detected_ham  = 0;
    my $i             = 0;
    my $len           = scalar keys %{$hr};
    my @files_spam;
    my @files_ham;
    my @cur_spam;
    my @cur_ham;
    my $check_func;

    if ($use_dspam) {
        $check_func = \&check_dspam;
    }
    elsif ($use_bogofilter) {
        $check_func = \&check_bogofilter;
    }
    else {
        $check_func = \&check_rspamc;
    }

    while ( my ( $fn, $spam ) = each( %{$hr} ) ) {
        if ($spam) {
            if ( scalar @cur_spam >= $parallel || $i == $len - 1 ) {
                push @cur_spam, $fn;
                push @files_spam, [@cur_spam];
                @cur_spam = ();
            }
            else {
                push @cur_spam, $fn;
            }
        }
        else {
            if ( scalar @cur_ham >= $parallel || $i == $len - 1 ) {
                push @cur_ham, $fn;
                push @files_ham, [@cur_ham];
                @cur_ham = ();
            }
            else {
                push @cur_ham, $fn;
            }
        }
    }

    shuffle_array( \@files_spam );

    foreach my $fn (@files_spam) {
        my $r = $check_func->( $fn, 1, \$fp_ham, \$fn_spam, \$detected_spam );
        $total_spam += $r;
        $processed  += $r;
    }

    shuffle_array( \@files_ham );

    foreach my $fn (@files_ham) {
        my $r = $check_func->( $fn, 0, \$fp_spam, \$fn_ham, \$detected_ham );
        $total_ham += $r;
        $processed += $r;
    }

    printf "Scanned %d messages
%d spam messages (%d detected)
%d ham messages (%d detected)\n", $processed, $total_spam, $detected_spam, $total_ham, $detected_ham;

    printf "\nHam FP rate: %.2f%% (%d messages)
Ham FN rate: %.2f%% (%d messages)\n", $fp_ham / $total_ham * 100.0, $fp_ham, $fn_ham / $total_ham * 100.0, $fn_ham;

    printf "\nSpam FP rate: %.2f%% (%d messages)
Spam FN rate: %.2f%% (%d messages)\n",
      $fp_spam / $total_spam * 100.0, $fp_spam,
      $fn_spam / $total_spam * 100.0, $fn_spam;
}

if ( !$spam_dir || !$ham_dir ) {
    die "spam or/and ham directories are not specified";
}

my @spam_samples;
my @ham_samples;

read_dir_files( $spam_dir, \@spam_samples );
read_dir_files( $ham_dir,  \@ham_samples );
shuffle_array( \@spam_samples );
shuffle_array( \@ham_samples );

if ( !$check_only ) {
    my $learned = 0;
    my $t0      = [gettimeofday];
    $learned = learn_samples( \@ham_samples, \@spam_samples );
    my $t1 = [gettimeofday];

    printf "Learned classifier, %d items processed, %.2f seconds elapsed\n", $learned, tv_interval( $t0, $t1 );
}

my %validation_set;
my $len = int( scalar @spam_samples * $train_fraction );
for ( my $i = $len ; $i < scalar @spam_samples ; $i++ ) {
    $validation_set{ $spam_samples[$i] } = 1;
}

$len = int( scalar @ham_samples * $train_fraction );
for ( my $i = $len ; $i < scalar @spam_samples ; $i++ ) {
    $validation_set{ $ham_samples[$i] } = 0;
}

cross_validate( \%validation_set );

__END__

=head1 NAME

classifier_test.pl - test various parameters for a classifier

=head1 SYNOPSIS

classifier_test.pl [options]

 Options:
   --spam                 Directory with spam files
   --ham                  Directory with ham files
   --spam-symbol          Symbol for spam (default: BAYES_SPAM)
   --ham-symbol           Symbol for ham (default: BAYES_HAM)
   --classifier           Classifier to test (default: bayes)
   --timeout              Timeout for rspamc (default: 10)
   --parallel             Parallel execution (default: 1)
   --help                 Brief help message
   --man                  Full documentation

=head1 OPTIONS

=over 8

=item B<--spam>

Directory with spam files.

=item B<--ham>

Directory with ham files.

=item B<--classifier>

Specifies classifier name to test.

=item B<--help>

Print a brief help message and exits.

=item B<--man>

Prints the manual page and exits.

=back

=head1 DESCRIPTION

B<classifier_test.pl> is intended to test Rspamd classifier for false positives, false negatives and other parameters.
It uses half of the corpus for training and half for cross-validation.

=cut
