package rspamd;

use 5.006001;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

our $VERSION = '0.0.1';

require XSLoader;
XSLoader::load('rspamd', $VERSION);
1;
__END__

=head1 NAME

rspamd - Perl interface to the rspamd API

=head1 SYNOPSIS

  use rspamd;

=head1 DESCRIPTION

TODO: Not ready yet

=cut
