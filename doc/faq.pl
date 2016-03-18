#!/usr/bin/env perl

use warnings;
use strict;
use Data::Dumper;

my $state = 0;

my @sections;
my $cur_section;
my $cur_question;

sub start_section {
	my ($section) = @_;

	my $anchor = lc $section;
	chomp $anchor;
	$anchor =~ s/\s/-/g;
	$anchor =~ tr/.,`'"_//d;

	my %ht = (
		questions => [],
		anchor => $anchor,
		topic => $section,
	);

	$cur_section = \%ht;
	push @sections, $cur_section;
}

sub start_question {
	my ($question) = @_;

	my $anchor = lc $question;
	chomp $anchor;
	$anchor =~ s/\s/-/g;
	$anchor =~ tr/.,`'"_//d;

	my %ht = (
		data => '',
		anchor => $anchor,
		topic => $question,
	);

	$cur_question = \%ht;
	push @{$cur_section->{'questions'}}, $cur_question;
}

while (<>) {
	if ($state == 0) {
		if (/^##\s(.*)$/) {
			$state = 1;
			start_section $1;
		}
		else {
			print $_;
		}
	}
	elsif ($state == 1) {
		if (/^###\s(.*)$/) {
			$state = 2;
			start_question $1;
		}
	}
	elsif ($state == 2) {
		if (/^###\s(.*)$/) {
			$state = 2;
			start_question $1;
		}
		elsif (/^##\s(.*)$/) {
			$state = 1;
			start_section $1;
		}
		else {
			if (/^```(\w+)/) {
				$cur_question->{'data'} .= "{% highlight $1 %}\n";
				$state = 3;
			}
			else {
				$cur_question->{'data'} .= $_;
			}
		}
	}
	elsif ($state == 3) {
		if (/^```\s*$/) {
			$state = 2;
			$cur_question->{'data'} .= "{% endhighlight %}\n";
		}
		else {
			$cur_question->{'data'} .= $_;
		}
	}
}

# Table of content
print "## Table of content\n";

foreach my $section (@sections) {
	print "* [$section->{'topic'}](#$section->{'anchor'})\n";

	my $j = 1;
	foreach my $question (@{$section->{'questions'}}) {
		print "    ${j}. [$question->{'topic'}](#$question->{'anchor'})\n";
		$j ++;
	}
}

print "\n";

foreach my $section (@sections) {
	print "## $section->{'topic'}\n\n";

	foreach my $question (@{$section->{'questions'}}) {
		print "### $question->{'topic'}\n";
		print $question->{'data'};
		print "Back to [content](#table-of-content)\n\n";
	}
}