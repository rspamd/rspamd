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

sub sort_func {
	my ($a, $b) = @_;

	if ($a =~ /^rspamd_[a-z]+\..*$/) {
		if ($b =~ /^rspamd_[a-z]+\..*$/) {
			# All module names
			return $a cmp $b;
		}
		else {
			return -1;
		}
	}
	elsif ($b =~ /^rspamd_[a-z]+\..*$/) {
		return 1;
	}
	
	return $a cmp $b;
}

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
		print "\n##Methods\n\nThe module defines the following methods.\n\n";
		foreach my $fname (sort {sort_func($a, $b)} keys %{$m->{'functions'}}) {
			my $f = $m->{'functions'}{$fname};
			print <<EOD;
##`$fname`

$f->{'data'}
EOD
			print "\n**Parameters:**\n\n";
			if ($f->{'params'} && scalar @{$f->{'params'}} > 0) {
				foreach (@{$f->{'params'}}) {
					if ($_->{'type'}) {
						print "- `$_->{'name'} \{$_->{'type'}\}`: $_->{'description'}\n";
					}
					else {
						print "- `$_->{'name'}`: $_->{'description'}\n";
					}
				}
			}
			else {
				print "\tnothing\n";
			}
			print "\n**Returns:**\n\n";
			if ($f->{'return'} && $f->{'return'}->{'description'}) {
				$_ = $f->{'return'};
				if ($_->{'type'}) {
					print "- `\{$_->{'type'}\}`: $_->{'description'}\n";
				}
				else {
					print "- $_->{'description'}\n";
				}
			}
			else {
				print "\tnothing\n";
			}
			if ($f->{'example'}) {
				print <<EOD;

Example:

~~~lua
$f->{'example'}
~~~
EOD
			}
			print "\nBack to [module description](#mod_$mname).\n\n";
			
		}
		print "\nBack to [top](#).\n\n";
	}
}

sub parse_function {
	my ($func, @data) = @_;
	
	my ($name) = ($func =~ /^\@function\s*(.+)\s*$/);

	$functions{$name} = {};
	
	my $f = $functions{$name};
	my $example = 0;

	foreach(@data) {
		if (/^\@param\s*(?:\{([^}]+)\})?\s*(\S+)\s*(.+)?\s*$/) {
			my $p = { name => $2, type => $1, description => $3};
			push @{$f->{'params'}}, $p;
		}
		elsif (/^\@return\s*(?:\{([^}]+)\})?\s*(.+)?\s*$/) {
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
#print Dumper(\%modules);
print_markdown;
