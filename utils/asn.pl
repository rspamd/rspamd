#!/usr/bin/env perl

use warnings;
use strict;
use Pod::Usage;
use Getopt::Long;
use File::Fetch;
use LWP::Simple;
use PerlIO::gzip;
use File::Basename;
use Net::MRT;
use URI;
use Data::Dumper;

$LWP::Simple::ua->show_progress(1);

my %config = (
  asn_sources => [
    'ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest',
    'ftp://ftp.ripe.net/ripe/stats/delegated-ripencc-latest',
    'ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest',
    'ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest',
    'ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest'
  ],
  bgp_sources => ['http://data.ris.ripe.net/rrc00/latest-bview.gz']
);

my $download_asn    = 0;
my $download_bgp    = 0;
my $download_target = "./";
my $help            = 0;
my $man             = 0;

GetOptions(
  "download-asn" => \$download_asn,
  "download-bgp" => \$download_bgp,
  "target=s"     => \$download_target,
  "help|?"       => \$help,
  "man"          => \$man
) or pod2usage(2);

pod2usage(1) if $help;
pod2usage( -exitval => 0, -verbose => 2 ) if $man;

sub download_file {
  my ($u) = @_;

  print "Fetching $u\n";
  my $ff = File::Fetch->new( uri => $u );
  my $where = $ff->fetch($download_target) or die $ff->error;

  return $where;
}

if ($download_asn) {
  foreach my $u ( @{ $config{'asn_sources'} } ) {
    download_file($u);
  }
}

if ($download_bgp) {
  foreach my $u ( @{ $config{'bgp_sources'} } ) {
    download_file($u);
  }
}

# Now load BGP data
my $networks = {};

foreach my $u ( @{ $config{'bgp_sources'} } ) {
  my $parsed = URI->new($u);
  my $fname  = $download_target . basename( $parsed->path );
  open( my $fh, "<:gzip", $fname )
    or die "Cannot open $fname: $!";

  while ( my $dd = eval { Net::MRT::mrt_read_next($fh) } ) {
    if ( $dd->{'subtype'} == 2 && $dd->{'prefix'} && $dd->{'bits'} ) {
      my $entry = $dd->{'entries'}->[0];
      my $net   = $dd->{'prefix'} . '/' . $dd->{'bits'};
      if ( $entry && $entry->{'AS_PATH'} ) {
        my $as = $entry->{'AS_PATH'}->[-1];
        if ( !$networks->{$as} ) {
          $networks->{$as} = { nets => [$net], };
        }
        else {
          push @{ $networks->{$as}->{'nets'} }, $net;
        }
      }
    }
  }
}

# Now roughly detect countries
foreach my $u ( @{ $config{'asn_sources'} } ) {
  my $parsed = URI->new($u);
  my $fname  = $download_target . basename( $parsed->path );
  open( my $fh, "<", $fname ) or die "Cannot open $fname: $!";

  while (<$fh>) {
    next if /^\#/;
    chomp;
    my @elts = split /\|/;

    if ( $elts[2] eq 'asn' && $elts[3] ne '*' ) {
      my $as_start = int( $elts[3] );
      my $as_end   = $as_start + int( $elts[4] );

      for ( my $as = $as_start ; $as < $as_end ; $as++ ) {
        if ( $networks->{"$as"} ) {
          $networks->{"$as"}->{'country'} = $elts[1];
          $networks->{"$as"}->{'rir'} = $elts[0];
        }
      }
    }
  }
}

while ( my ( $k, $v ) = each(%{$networks}) ) {
  foreach my $n (@{$v->{'nets'}}) {
    # "15169 | 8.8.8.0/24 | US | arin |" for 8.8.8.8
    if ($v->{'country'}) {
      printf "%s %s|%s|%s|%s|\n", $n, $k, $n, $v->{'country'}, $v->{'rir'};
    }
    else {
      printf "%s %s|%s|%s|%s|\n", $n, $k, $n, 'UN', 'UN';
    }
  }
}

print "\$SOA 43200 ns1.asn.rspamd.com support.rspamd.com 0 600 300 86400 300\n";
print "\$NS 43200 ns1.asn.rspamd.com\n";

__END__

=head1 NAME

asn.pl - download and parse ASN data for Rspamd

=head1 SYNOPSIS

asn.pl [options]

 Options:
   --download-asn         Download ASN data from RIR
   --download-bgp       Download GeoIP data from Maxmind
   --target               Where to download files (default: current dir)
   --help                 Brief help message
   --man                  Full documentation

=head1 OPTIONS

=over 8

=item B<--download-asn>

Download ASN data from RIR.

=item B<--download-bgp>

Download GeoIP data from Ripe

=item B<--target>

Specifies where to download files.

=item B<--help>

Print a brief help message and exits.

=item B<--man>

Prints the manual page and exits.

=back

=head1 DESCRIPTION

B<asn.pl> is intended to download ASN data and GeoIP data and create a rbldnsd zone.

=cut
