#!/usr/bin/env perl

use strict;
use warnings;
use Data::Dumper;
use Digest::MD5 qw(md5_hex);

use constant {
	STATE_READ_SKIP    => 0,
	STATE_READ_CONTENT => 1,
};

my $state = STATE_READ_SKIP;
my $content;
my %modules = ();
my $cur_module;

sub print_module_markdown {
	my ( $mname, $m ) = @_;

	print <<EOD;
## Module `$mname`  {#$m->{'id'}}

$m->{'data'}
EOD
	if ( $m->{'example'} ) {
		print <<EOD;

Example:

~~~lua
$m->{'example'}
~~~
EOD
	}
	sub print_func {
		my ($f) = @_;
		
		my $name = $f->{'name'};
		my $id = $f->{'id'};
		print ": [`$name`](#$id)\n";
	}
	
	print "\n###Brief content:\n\n";
	print "**Functions**:\n";
	foreach (@{$m->{'functions'}}) {
		print_func($_);
	}
	print "\n\n**Methods**:\n";
	foreach (@{$m->{'methods'}}) {
		print_func($_);
	}
}

sub print_function_markdown {
	my ( $type, $fname, $f ) = @_;

	print <<EOD;
### $type `$fname`  {#$f->{'id'}}

$f->{'data'}
EOD
	print "\n**Parameters:**\n\n";
	if ( $f->{'params'} && scalar @{ $f->{'params'} } > 0 ) {
		foreach ( @{ $f->{'params'} } ) {
			if ( $_->{'type'} ) {
				print
				  "- `$_->{'name'} \{$_->{'type'}\}`: $_->{'description'}\n";
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
	if ( $f->{'return'} && $f->{'return'}->{'description'} ) {
		$_ = $f->{'return'};
		if ( $_->{'type'} ) {
			print "- `\{$_->{'type'}\}`: $_->{'description'}\n";
		}
		else {
			print "- $_->{'description'}\n";
		}
	}
	else {
		print "\tnothing\n";
	}
	if ( $f->{'example'} ) {
		print <<EOD;

Example:

~~~lua
$f->{'example'}
~~~
EOD
	}
}

sub print_markdown {
	while ( my ( $mname, $m ) = each %modules ) {
		print_module_markdown( $mname, $m );

		print "\n## Functions\n\nThe module `$mname` defines the following functions.\n\n";
		foreach ( @{ $m->{'functions'} } ) {
			print_function_markdown( "Function", $_->{'name'}, $_ );
			print "\nBack to [module description](#$m->{'id'}).\n\n";

		}
		print "\n## Methods\n\nThe module `$mname` defines the following methods.\n\n";
		foreach ( @{ $m->{'methods'} } ) {
			print_function_markdown( "Method", $_->{'name'}, $_ );
			print "\nBack to [module description](#$m->{'id'}).\n\n";

		}
		print "\nBack to [top](#).\n\n";
	}
}

sub parse_function {
	my ( $func, @data ) = @_;

	my ( $type, $name ) = ( $func =~ /^\@(\w+)\s*(.+)\s*$/ );

	my $f = {
		name    => $name,
		data    => '',
		example => undef,
		id => substr('f' . md5_hex($name), 0, 5),
	};
	my $example = 0;
	
	foreach (@data) {
		if (/^\@param\s*(?:\{([^}]+)\})?\s*(\S+)\s*(.+)?\s*$/) {
			my $p = { name => $2, type => $1, description => $3 };
			push @{ $f->{'params'} }, $p;
		}
		elsif (/^\@return\s*(?:\{([^}]+)\})?\s*(.+)?\s*$/) {
			my $r = { type => $1, description => $2 };
			$f->{'return'} = $r;
		}
		elsif (/^\@example$/) {
			$example = 1;
		}
		elsif ( $_ ne $func ) {
			if ($example) {
				$f->{'example'} .= $_;
			}
			else {
				$f->{'data'} .= $_;
			}
		}
	}
	if ( $f->{'data'} ) {
		chomp $f->{'data'};
	}
	if ( $f->{'example'} ) {
		chomp $f->{'example'};
	}

	if ( $type eq "function" ) {
		push @{ $cur_module->{'functions'} }, $f;
	}
	else {
		push @{ $cur_module->{'methods'} }, $f;
	}
}

sub parse_module {
	my ( $module, @data ) = @_;

	my ($name) = ( $module =~ /^\@module\s*(.+)\s*$/ );

	$modules{$name} = {
		functions => [],
		methods   => [],
		data      => '',
		example   => undef,
		id => substr('m' . md5_hex($name), 0, 5),
	};
	my $f       = $modules{$name};
	my $example = 0;

	foreach (@data) {
		if (/^\@example$/) {
			$example = 1;
		}
		elsif ( $_ ne $module ) {
			if ($example) {
				$f->{'example'} .= $_;
			}
			else {
				$f->{'data'} .= $_;
			}
		}
	}
	if ( $f->{'data'} ) {
		chomp $f->{'data'};
	}
	if ( $f->{'example'} ) {
		chomp $f->{'example'};
	}
	$cur_module = $f;
}

sub parse_content {
	my @func = grep /^\@function|method.+$/, @_;
	if ( scalar @func > 0 ) {
		parse_function( $func[0], @_ );
	}
	else {
		my @module = grep /^\@module.+$/, @_;
		if ( scalar @module > 0 ) {
			parse_module( $module[0], @_ );
		}
	}
}

while (<>) {
	if ( $state == STATE_READ_SKIP ) {
		if ( $_ =~ /^\s*\/\*\*\*$/ ) {
			$state   = STATE_READ_CONTENT;
			$content = "";
		}
	}
	elsif ( $state == STATE_READ_CONTENT ) {
		if ( $_ =~ /^\s*\*\/$/ ) {
			$state = STATE_READ_SKIP;
			parse_content( split /^/, $content );
			$content = "";
		}
		else {
			my ($line) = ( $_ =~ /^(?:\s*\*\s)?(.+)\s*$/ );
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

#print Dumper( \%modules );
print_markdown;
