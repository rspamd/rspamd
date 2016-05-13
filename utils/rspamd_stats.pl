#!/usr/bin/env perl

use Data::Dumper;
use Getopt::Long;
use warnings;
use strict;
use Time::Piece;

my @symbols_search;
my $start = "";
my $end = "";
my $reject_score = 30.0;
my $junk_score = 7.5;
my $log_file = "/var/log/rspamd/rspamd.log";
my $dateformat = "%Y-%m-%d %H:%M:%S";

GetOptions(
  "reject-score=f" => \$reject_score,
  "junk-score=f" => \$junk_score,
  "start=s" => \$start,
  "end=s" => \$end,
  "symbol=s@" => \@symbols_search,
  "log=s" => \$log_file,
  "dateformat=s" => \$dateformat);

# Global vars
my $total = 0;
my $total_spam = 0;
my $total_junk = 0;
my $junk_symbols = 0;
my $spam_symbols = 0;
my $ham_symbols = 0;
my $ham_spam_change = 0;
my $ham_junk_change = 0;
my $diff_alpha = 0.1;
my %sym_res;

my $st = 0;
my $ed = 0;

if ($start ne "") {
  $st = Time::Piece->strptime($start, $dateformat);
}

if ($end ne "") {
  $ed = Time::Piece->strptime($end, $dateformat);
}

my $rspamd_log;

if ($log_file eq '-') {
  $rspamd_log = \*STDIN;
}
else {
  open($rspamd_log, '<', $log_file) or die "cannot open $log_file";
}

foreach my $s (@symbols_search) {
  $sym_res{$s} = {
    hits => 0,
    spam_hits => 0,
    junk_hits => 0,
    spam_change => 0,
    junk_change => 0,
    weight => 0,
  };
}

while(<$rspamd_log>) {
  if (/^.*rspamd_task_write_log.*$/) {
    my @elts = split /\s+/;
    my $ts = $elts[0] . ' ' . $elts[1];

    if ($st or $ed) {
      my $dt = Time::Piece->strptime($ts, $dateformat) or die "cannot parse $ts";

      if ($dt) {
        if ($st != 0 && $dt < $st) {
          next;
        }
        if ($ed != 0 && $dt > $ed) {
          next;
        }
      }
    }

    if ($_ !~ /\[(-?\d+(?:\.\d+)?)\/(-?\d+(?:\.\d+)?)\]\s+\[([^\]]+)\]/) {
      #print "BAD\n";
      next;
    }

    $total ++;
    my $score = $1 * 1.0;

    if ($score >= $reject_score) {
      $total_spam ++;
    }
    elsif ($score >= $junk_score) {
      $total_junk ++;
    }

    # Symbols
    my @symbols = split /,/, $3;

    foreach my $s (@symbols_search) {
      my @selected = grep /$s/, @symbols;

      if (scalar(@selected) > 0) {
        $selected[0] =~ /^[^\(]+\(([^\)]+)\).*$/;
        my $sym_score = $1;

        if ($sym_score < $diff_alpha) {
          next;
        }

        my $r = $sym_res{$s};
        $r->{hits} ++;
        $r->{weight} += $sym_score;
        my $is_spam = 0;
        my $is_junk = 0;

        if ($score >= $reject_score) {
          $is_spam = 1;
          $r->{spam_hits} ++;
        }
        elsif ($score >= $junk_score) {
          $is_junk = 1;
          $r->{junk_hits} ++;
        }

        my $score_without = $score - $sym_score;

        if ($is_spam && $score_without < $reject_score) {
          $r->{spam_change} ++;
        }
        if ($is_junk && $score_without < $junk_score) {
          $r->{junk_change} ++;
        }
      }
    }
  }
}

my $total_ham = $total - ($total_spam + $total_junk);

if ($total > 0) {
  while (my ($s, $r) = each(%sym_res)) {
    if ($r->{hits} > 0) {
      my $th = $r->{hits};
      my $sh = $r->{spam_hits};
      my $jh = $r->{junk_hits};
      my $hh = $r->{hits} - $sh - $jh;
      my $htp = $hh * 100.0 / $total_ham if $total_ham != 0;
      my $stp = $sh * 100.0 / $total_spam if $total_spam != 0;
      my $jtp = $jh * 100.0 / $total_junk if $total_junk != 0;
      printf "Symbol: %s (weight %.3f) (%d hits, %.3f%%)\nHam hits: %d (%.3f%%), total ham: %d (ham with $s: %.3f%%)\nSpam hits: %d (%.3f%%), total spam: %d (spam with $s: %.3f%%)\nJunk hits: %d (%.3f%%), total junk: %d (junk with $s: %.3f%%)\n",
          $s, $r->{weight} / $r->{hits}, $th, ($th / $total * 100.0),
          $hh, ($hh / $th * 100.0), $total_ham, ($htp or 0),
          $sh, ($sh / $th * 100.0), $total_spam, ($stp or 0),
          $jh, ($jh / $th * 100.0), $total_junk, ($jtp or 0);
      my $schp = $r->{spam_change} / $total_spam * 100.0 if $total_spam;
      my $jchp = $r->{junk_change} / $total_junk * 100.0 if $total_junk;
      printf "Spam changes (ham/junk -> spam): %d (%.3f%%), total percentage (changes / spam hits): %.3f%%\nJunk changes (ham -> junk): %d (%.3f%%), total percentage (changes / junk hits): %.3f%%\n",
          $r->{spam_change}, ($r->{spam_change} / $th * 100.0), ($schp or 0),
          $r->{junk_change}, ($r->{junk_change} / $th * 100.0), ($jchp or 0);
    }
    else {
      print "Symbol $s has not been met\n";
    }

    print '*' x 20 . "\n";
  }
}
