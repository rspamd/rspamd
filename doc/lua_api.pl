#!/usr/bin/env perl

use strict;
use warnings;
use Data::Dumper;
use Storable qw/dclone/;

use constant {
	STATE_READ_SKIP => 0,
	STATE_READ_CONTENT => 1,
};

my $state = STATE_READ_SKIP;
my $content;
my %functions = ();
my %modules = ();
my $cur_module;

sub print_markdown {
	while (my ($mname, $m) = each %modules) {
		print <<EOD;
#$mname {#mod_$mname}

$m->{'data'}
EOD
		if ($m->{'example'}) {
			print <<EOD;

Example:

~~~lua
$m->{'example'}
~~~
EOD
		}
		print "##Methods\n\nThe module defines the following methods.\n\n";
		while (my ($fname, $f) = each %{$m->{'functions'}}) {
			print <<EOD;
##`$fname`

$f->{'data'}
EOD
			print "\n*Parameters*\n";
			foreach (@{$f->{'params'}}) {
				if ($_->{'type'}) {
					print "\t`$_->{'name'} \{$_->{'type'}\}` $_->{'description'}\n";
				}
				else {
					print "\t`$_->{'name'}` $_->{'description'}\n";
				}
			}
			print "\n*Returns*\n";
			if ($f->{'return'} && $f->{'return'}->{'description'}) {
				$_ = $f->{'return'};
				if ($_->{'type'}) {
					print "\t`\{$_->{'type'}\}` $_->{'description'}\n";
				}
				else {
					print "\t$_->{'description'}\n";
				}
			}
			else {
				print "\tnothing\n";
			}
			if ($f->{'example'}) {
				print <<EOD;

Example:
m
~~~lua
$f->{'example'}
~~~
EOD
			}
			print "\nBack to [module description](#mod_$mname).\n";
			
		}
		print "\nBack to [top](#).\n";
	}
}

sub parse_function {
	my ($func, @data) = @_;
	
	my ($name) = ($func =~ /^\@function\s*(.+)\s*$/);

	$functions{$name} = {};
	
	my $f = $functions{$name};
	my $example = 0;

	foreach(@data) {
		if (/^\@param\s*(?:\{([a-zA-Z])\})?\s*(\S+)\s*(.+)?\s*$/) {
			my $p = { name => $2, type => $1, description => $3};
			push @{$f->{'params'}}, $p;
		}
		elsif (/^\@return\s*(?:\{([a-zA-Z])\})?\s*(.+)?\s*$/) {
			my $r = { type => $1, description => $2 };
			$f->{'return'} = $r;
		}
		elsif (/^\@example$/) {
			$example = 1;
		}
		elsif ($_ ne $func) {
			if ($example) {
				$f->{'example'} .= $_;
			}
			else {
				$f->{'data'} .= $_;
			}
		}
	}
	if ($f->{'data'}) {
		chomp $f->{'data'};
	}
	if ($f->{'example'}) {
		chomp $f->{'example'};	
	}
}

sub parse_module {
	my ($module, @data) = @_;
	
	my ($name) = ($module =~ /^\@module\s*(.+)\s*$/);
	$modules{$name} = { functions => dclone(\%functions) };
	%functions = ();
	
	my $f = $modules{$name};
	my $example = 0;

	foreach(@data) {
		if (/^\@example$/) {
			$example = 1;
		}
		elsif ($_ ne $module) {
			if ($example) {
				$f->{'example'} .= $_;
			}
			else {
				$f->{'data'} .= $_;
			}
		}
	}
	if ($f->{'data'}) {
		chomp $f->{'data'};
	}
	if ($f->{'example'}) {
		chomp $f->{'example'};	
	}
	$cur_module = $f;
}

sub parse_content {
	my @func = grep /^\@function.+$/, @_;
	if (scalar @func > 0) {
		parse_function($func[0], @_);
	}
	else {
		my @module = grep /^\@module.+$/, @_;
		if (scalar @module > 0) {
			parse_module($module[0], @_);	
		}
	}
}

while(<>) {
	if ($state == STATE_READ_SKIP) { 
		if ($_ =~ /^\s*\/\*\*\*$/) {
			$state = STATE_READ_CONTENT;
			$content = "";
		}
	}
	elsif ($state == STATE_READ_CONTENT) {
		if ($_ =~ /^\s*\*\/$/) {
			$state = STATE_READ_SKIP;
			parse_content(split /^/, $content);
			$content = "";
		}
		else {
			my ($line) = ($_ =~ /^\s*(?:\*\s?)(.+)\s*$/);
			if ($line) {
				$content .= $line . "\n";
			}
			else {
				# Preserve empty lines
				$content .= "\n";
			}
		}
	}
}

$cur_module->{'functions'} = dclone(\%functions);
print_markdown;
