#!/usr/bin/env perl

$VERSION = "0.1";

use strict;
use warnings;
use Data::Dumper;
use Digest::MD5 qw(md5_hex);

my @modules;
my %options = ();
my $cur_module;
my $example_language = "lua";

my %languages = (
    c => {
        start  => qr/^\s*\/\*\*\*(?:\s*|(\s+\S.+\s*))$/,
        end    => qr/^\s*\*+\/\s*$/,
        filter => qr/^(?:\s*\*+\s?)?(\s*[^*].+)\s*$/,
    },
    lua => {
        start  => qr/^\s*\--\[\[\[\s*$/,
        end    => qr/^\s*--\]\]\s*/,
        filter => qr/^(?:\s*--\s)?(\s*\S.+)\s*$/,
    },
);

my $function_re = qr/^\s*\@(function|fn|method)\s*(\S.+)$/oi;
my $module_re = qr/^\s*\@(?:module|file)\s*(\S.+)$/oi;

my $language;

sub print_module_markdown {
    my ( $mname, $m ) = @_;

    my $idline = $options{g} ? "" : " {#$m->{'id'}}";
    print <<EOD;
## Module `$mname`$idline

$m->{'data'}
EOD
    if ( $m->{'example'} ) {
        print <<EOD;

Example:

~~~$m->{'example_language'}
$m->{'example'}
~~~
EOD
    }

    sub print_func {
        my ($f) = @_;

        my $name = $f->{'name'};
        my $id   = $f->{'id'};
        if ($f->{'brief'}) {
            print "> [`$name`](#$id): ". $f->{'brief'} . "\n\n";
        }
        else {
            print "> [`$name`](#$id)\n\n";
        }
    }

    print "\n### Brief content:\n\n";
    if (scalar(@{ $m->{'functions'} }) > 0) {
        print "**Functions**:\n\n";
        foreach ( @{ $m->{'functions'} } ) {
        print_func($_);
        }
    }
    if (scalar(@{ $m->{'methods'} }) > 0) {
        print "\n\n**Methods**:\n\n";
        foreach (@{ $m->{'methods'} }) {
            print_func($_);
        }
    }
}

sub print_function_markdown {
    my ( $type, $fname, $f ) = @_;

    my $idline = $options{g} ? "" : " {#$f->{'id'}}";
    print <<EOD;
### $type `$fname`$idline

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

~~~$f->{'example_language'}
$f->{'example'}
~~~
EOD
    }
}

sub print_markdown {
    for my $m (@modules) {
        my $mname = $m->{name};
        print_module_markdown( $mname, $m );

        if (scalar(@{ $m->{'functions'} }) > 0) {
            print
                "\n## Functions\n\nThe module `$mname` defines the following functions.\n\n";
            foreach (@{ $m->{'functions'} }) {
                print_function_markdown( "Function", $_->{'name'}, $_ );
                print "\nBack to [module description](#$m->{'id'}).\n\n";

            }
        }

        if (scalar(@{ $m->{'methods'} }) > 0) {
            print
                "\n## Methods\n\nThe module `$mname` defines the following methods.\n\n";
            foreach (@{ $m->{'methods'} }) {
                print_function_markdown( "Method", $_->{'name'}, $_ );
                print "\nBack to [module description](#$m->{'id'}).\n\n";

            }
        }

        print "\nBack to [top](#).\n\n";
    }
}

sub make_id {
    my ( $name, $prefix ) = @_;

    if ( !$prefix ) {
        $prefix = "f";
    }
    if ( !$options{g} ) {

        # Kramdown/pandoc version of ID's
        $name =~ /^(\S+).*$/;
        return substr( substr( $prefix, 0, 1 ) . md5_hex($1), 0, 6 );
    }
    else {
        my $input = lc $prefix . "-" . $name;
        my $id = join '-', split /\s+/, $input;
        $id =~ s/[^\w_-]+//g;
        return $id;
    }
}

sub substitute_data_keywords {
    my ($line) = @_;

    if ( $line =~ /^.*\@see\s+(\S+)\s*.*$/ ) {
        my $name = $1;
        my $id   = make_id($name);
        return $line =~ s/\@see\s+\S+/[`$name`](#$id)/r;
    }

    return $line;
}

sub parse_function {
    my ( $func, @data ) = @_;

    my ( $type, $name ) = ( $func =~ $function_re );

    chomp $name;

    my $f = {
        name             => $name,
        data             => '',
        example          => undef,
        example_language => $example_language,
        id               => make_id( $name, $type ),
    };
    my $example = 0;

    foreach (@data) {
        if (/^\s*\@param\s*(?:\{([^}]+)\})?\s*(\S+)\s*(.+)?\s*$/) {
            my $p = { name => $2, type => $1, description => $3 };
            push @{ $f->{'params'} }, $p;
        }
        elsif (/^\s*\@return\s*(?:\{([^}]+)\})?\s*(.+)?\s*$/) {
            my $r = { type => $1, description => $2 };
            $f->{'return'} = $r;
        }
        elsif (/^\s*\@brief\s*(\S.+)$/) {
            $f->{'brief'} = $1;
        }
        elsif (/^\s*\@example\s*(\S)?\s*$/) {
            $example = 1;
            if ($1) {
                $f->{'example_language'} = $1;
            }
        }
        elsif ( $_ ne $func ) {
            if ($example) {
                $f->{'example'} .= $_;
            }
            else {
                $f->{'data'} .= substitute_data_keywords($_);
            }
        }
    }
    if ( $f->{'data'} ) {
        chomp $f->{'data'};
    }
    elsif ($f->{'brief'}) {
        chomp $f->{'brief'};
        $f->{'data'} = $f->{'brief'};
    }
    if ( $f->{'example'} ) {
        chomp $f->{'example'};
    }

    if ( $type eq "method" ) {
        push @{ $cur_module->{'methods'} }, $f;
    }
    else {
        push @{ $cur_module->{'functions'} }, $f;
    }
}

sub parse_module {
    my ( $module, @data ) = @_;
    my ( $name ) = ( $module =~ $module_re );

    chomp $name;

    my $f = {
        name             => $name,
        functions        => [],
        methods          => [],
        data             => '',
        example          => undef,
        example_language => $example_language,
        id               => make_id( $name, "module" ),
    };
    my $example = 0;

    foreach (@data) {
        if (/^\s*\@example\s*(\S)?\s*$/) {
            $example = 1;
            if ($1) {
                $f->{'example_language'} = $1;
            }
        }
        elsif (/^\s*\@brief\s*(\S.+)$/) {
            $f->{'brief'} = $1;
        }
        elsif ( $_ ne $module ) {
            if ($example) {
                $f->{'example'} .= $_;
            }
            else {
                $f->{'data'} .= substitute_data_keywords($_);
            }
        }
    }
    if ( $f->{'data'} ) {
        chomp $f->{'data'};
    }
    elsif ($f->{'brief'}) {
        chomp $f->{'brief'};
        $f->{'data'} = $f->{'brief'};
    }
    if ( $f->{'example'} ) {
        chomp $f->{'example'};
    }
    $cur_module = $f;
    push @modules, $f;
}

sub parse_content {
    my @func = grep /$function_re/, @_;
    if ( scalar @func > 0 ) {
        parse_function( $func[0], @_ );
    }

    my @module = grep /$module_re/, @_;
    if ( scalar @module > 0 ) {
        parse_module( $module[0], @_ );
    }
}

sub HELP_MESSAGE {
    print STDERR <<EOF;
Utility to convert doxygen comments to markdown.

usage: $0 [-hg] [-l language] < input_source > markdown.md

 -h        : this (help) message
 -e        : sets default example language (default: lua)
 -l        : sets input language (default: c)
 -g        : use github flavoured markdown (default: kramdown/pandoc)
EOF
    exit;
}

$Getopt::Std::STANDARD_HELP_VERSION = 1;
use Getopt::Std;
getopts( 'he:gl:', \%options );

HELP_MESSAGE() if $options{h};

$example_language = $options{e} if $options{e};
$language = $languages{ lc $options{l} } if $options{l};

if ( !$language ) {
    $language = $languages{c};
}

use constant {
    STATE_READ_SKIP    => 0,
    STATE_READ_CONTENT => 1,
    STATE_READ_ENUM => 2,
    STATE_READ_STRUCT => 3,
};

my $state = STATE_READ_SKIP;
my $content;

while (<>) {
    if ( $state == STATE_READ_SKIP ) {
        if ( $_ =~ $language->{start} ) {
            $state = STATE_READ_CONTENT;
            if (defined($1)) {
                chomp($content = $1);
                $content =~ tr/\r//d;
                $content .= "\n";
            }
            else {
                $content = "";
            }
        }
    }
    elsif ( $state == STATE_READ_CONTENT ) {
        if ( $_ =~ $language->{end} ) {
            $state = STATE_READ_SKIP;
            parse_content( split /^/, $content );
            $content = "";
        }
        else {
            my ($line) = ( $_ =~ $language->{filter} );

            if ($line) {
                $line =~ tr/\r//d;
                $content .= $line . "\n";
            }
            else {
                # Preserve empty lines
                $content .= "\n";
            }
        }
    }
}

#print Dumper( \@modules );
print_markdown;
