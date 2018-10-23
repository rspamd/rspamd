#!/usr/bin/env perl

# This script is a very simple prototype to learn fann from rspamd logs
# For now, it is intended for internal use only

use strict;
use warnings FATAL => 'all';
use AI::FANN qw(:all);
use Getopt::Std;

my %sym_idx;      # Symbols by index
my %sym_names;    # Symbols by name
my $num = 1;      # Number of symbols
my @spam;
my @ham;
my $max_samples  = -1;
my $split        = 1;
my $preprocessed = 0;    # output is in format <score>:<0|1>:<SYM1,...SYMN>
my $score_spam   = 12;
my $score_ham    = -6;

sub process {
    my ( $input, $spam, $ham ) = @_;
    my $samples = 0;

    while (<$input>) {
        if ( !$preprocessed ) {
            if (/^.*rspamd_task_write_log.*: \[(-?\d+\.?\d*)\/(\d+\.?\d*)\]\s*\[(.+)\].*$/) {
                if ( $1 > $score_spam ) {
                    $_ = "$1:1: $3";
                }
                elsif ( $1 < $score_ham ) {
                    $_ = "$1:0: $3\n";
                }
                else {
                    # Out of boundary
                    next;
                }
            }
            else {
                # Not our log message
                next;
            }
        }

        $_ =~ /^(-?\d+\.?\d*):([01]):\s*(\S.*)$/;

        my $is_spam = 0;

        if ( $2 == 1 ) {
            $is_spam = 1;
        }

        my @ar = split /,/, $3;
        my %sample;

        foreach my $sym (@ar) {
            chomp $sym;
            if ( !$sym_idx{$sym} ) {
                $sym_idx{$sym}   = $num;
                $sym_names{$num} = $sym;
                $num++;
            }

            $sample{ $sym_idx{$sym} } = 1;
        }

        if ($is_spam) {
            push @{$spam}, \%sample;
        }
        else {
            push @{$ham}, \%sample;
        }

        $samples++;
        if ( $max_samples > 0 && $samples > $max_samples ) {
            return;
        }
    }
}

# Shuffle array
sub fisher_yates_shuffle {
    my $array = shift;
    my $i     = @$array;

    while ( --$i ) {
        my $j = int rand( $i + 1 );
        @$array[ $i, $j ] = @$array[ $j, $i ];
    }
}

# Train network
sub train {
    my ( $ann, $sample, $result ) = @_;

    my @row;

    for ( my $i = 1 ; $i < $num ; $i++ ) {
        if ( $sample->{$i} ) {
            push @row, 1;
        }
        else {
            push @row, 0;
        }
    }

    #print "@row -> @{$result}\n";

    $ann->train( \@row, \@{$result} );
}

sub test {
    my ( $ann, $sample ) = @_;

    my @row;

    for ( my $i = 1 ; $i < $num ; $i++ ) {
        if ( $sample->{$i} ) {
            push @row, 1;
        }
        else {
            push @row, 0;
        }
    }

    my $ret = $ann->run( \@row );

    return $ret;
}

my %opts;
getopts( 'o:i:s:n:t:hpS:H:', \%opts );

if ( $opts{'h'} ) {
    print "$0 [-i input] [-o output] [-s scores] [-n max_samples] [-S spam_score] [-H ham_score] [-ph]\n";
    exit;
}

my $input = *STDIN;

if ( $opts{'i'} ) {
    open( $input, '<', $opts{'i'} ) or die "cannot open $opts{i}";
}

if ( $opts{'n'} ) {
    $max_samples = $opts{'n'};
}

if ( $opts{'t'} ) {

    # Test split
    $split = $opts{'t'};
}
if ( $opts{'p'} ) {
    $preprocessed = 1;
}

if ( $opts{'H'} ) {
    $score_ham = $opts{'H'};
}

if ( $opts{'S'} ) {
    $score_spam = $opts{'S'};
}

# ham_prob, spam_prob
my @spam_out = (1);
my @ham_out  = (0);

process( $input, \@spam, \@ham );
fisher_yates_shuffle( \@spam );
fisher_yates_shuffle( \@ham );

my $nspam = int( scalar(@spam) / $split );
my $nham  = int( scalar(@ham) / $split );

my $ann = AI::FANN->new_standard( $num - 1, ( $num + 2 ) / 2, 1 );

my @train_data;

# Train ANN
for ( my $i = 0 ; $i < $nham ; $i++ ) {
    push @train_data, [ $ham[$i], \@ham_out ];
}

for ( my $i = 0 ; $i < $nspam ; $i++ ) {
    push @train_data, [ $spam[$i], \@spam_out ];
}

fisher_yates_shuffle( \@train_data );

foreach my $train_row (@train_data) {
    train( $ann, @{$train_row}[0], @{$train_row}[1] );
}

print "Trained $nspam SPAM and $nham HAM samples\n";

# Now run fann
if ( $split > 1 ) {
    my $sample  = 0.0;
    my $correct = 0.0;
    for ( my $i = $nham ; $i < $nham * $split ; $i++ ) {
        my $ret = test( $ann, $ham[$i] );

        #print "@{$ret}\n";
        if ( @{$ret}[0] < 0.5 ) {
            $correct++;
        }
        $sample++;
    }

    print "Tested $sample HAM samples, correct matched: $correct, rate: " . ( $correct / $sample ) . "\n";

    $sample  = 0.0;
    $correct = 0.0;

    for ( my $i = $nspam ; $i < $nspam * $split ; $i++ ) {
        my $ret = test( $ann, $spam[$i] );

        #print "@{$ret}\n";
        if ( @{$ret}[0] > 0.5 ) {
            $correct++;
        }
        $sample++;
    }

    print "Tested $sample SPAM samples, correct matched: $correct, rate: " . ( $correct / $sample ) . "\n";
}

if ( $opts{'o'} ) {
    $ann->save( $opts{'o'} ) or die "cannot save ann into $opts{o}";
}

if ( $opts{'s'} ) {
    open( my $scores, '>', $opts{'s'} ) or die "cannot open score file $opts{'s'}";
    print $scores "{";
    for ( my $i = 1 ; $i < $num ; $i++ ) {
        my $n = $i - 1;
        if ( $i != $num - 1 ) {
            print $scores "\"$sym_names{$i}\":$n,";
        }
        else {
            print $scores "\"$sym_names{$i}\":$n}\n";
        }
    }
}
