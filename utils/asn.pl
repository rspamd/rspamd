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
$Net::MRT::USE_RFC4760 = -1;

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
my $v4              = 1;
my $v6              = 0;
my $parse           = 1;
my $v4_zone         = "asn.rspamd.com";
my $v6_zone         = "asn6.rspamd.com";
my $v4_file         = "asn.zone";
my $v6_file         = "asn6.zone";

GetOptions(
  "download-asn" => \$download_asn,
  "download-bgp" => \$download_bgp,
  "4!"           => \$v4,
  "6"            => \$v6,
  "parse!"       => \$parse,
  "target=s"     => \$download_target,
  "zone-v4=s"    => \$v4_zone,
  "zone-v6=s"    => \$v6_zone,
  "file-v4=s"    => \$v4_file,
  "file-v6=s"    => \$v6_file,
  "help|?"       => \$help,
  "man"          => \$man
) or pod2usage(2);

pod2usage(1) if $help;
pod2usage( -exitval => 0, -verbose => 2 ) if $man;

sub download_file {
  my ($u) = @_;

  print "Fetching $u\n";
  my $ff = File::Fetch->new( uri => $u );
  my $where = $ff->fetch( to => $download_target ) or die $ff->error;

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

if ( !$parse ) {
  exit 0;
}

my $v4_fh;
my $v6_fh;

if ($v4) {
  open( $v4_fh, ">", $v4_file ) or die "Cannot open $v4_file for writing: $!";
  print $v4_fh
    "\$SOA 43200 ns1.$v4_zone support.rspamd.com 0 600 300 86400 300\n";
  print $v4_fh "\$NS 43200 ns1.$v4_zone\n";
}
if ($v6) {
  open( $v6_fh, ">", $v6_file ) or die "Cannot open $v6_file for writing: $!";
  print $v6_fh
    "\$SOA 43200 ns1.$v6_zone support.rspamd.com 0 600 300 86400 300\n";
  print $v6_fh "\$NS 43200 ns1.$v6_zone\n";
}

# Now load BGP data
my $networks = {};

foreach my $u ( @{ $config{'bgp_sources'} } ) {
  my $parsed = URI->new($u);
  my $fname  = $download_target . '/' . basename( $parsed->path );
  open( my $fh, "<:gzip", $fname )
    or die "Cannot open $fname: $!";

  while ( my $dd = eval { Net::MRT::mrt_read_next($fh) } ) {
    if ( $dd->{'prefix'} && $dd->{'bits'} ) {
      next if $dd->{'subtype'} == 2 and !$v4;
      next if $dd->{'subtype'} == 4 and !$v6;
      my $entry = $dd->{'entries'}->[0];
      my $net   = $dd->{'prefix'} . '/' . $dd->{'bits'};
      if ( $entry && $entry->{'AS_PATH'} ) {
        my $as = $entry->{'AS_PATH'}->[-1];
        if ( !$networks->{$as} ) {
          if ( $dd->{'subtype'} == 2 ) {
            $networks->{$as} = { nets_v4 => [$net], nets_v6 => [] };
          }
          else {
            $networks->{$as} = { nets_v6 => [$net], nets_v4 => [] };
          }
        }
        else {
          if ( $dd->{'subtype'} == 2 ) {
            push @{ $networks->{$as}->{'nets_v4'} }, $net;
          }
          else {
            push @{ $networks->{$as}->{'nets_v6'} }, $net;
          }
        }
      }
    }
  }
}

# Now roughly detect countries
foreach my $u ( @{ $config{'asn_sources'} } ) {
  my $parsed = URI->new($u);
  my $fname  = $download_target . '/' . basename( $parsed->path );
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
          $networks->{"$as"}->{'rir'}     = $elts[0];
        }
      }
    }
  }
}

while ( my ( $k, $v ) = each( %{$networks} ) ) {
  if ($v4) {
    foreach my $n ( @{ $v->{'nets_v4'} } ) {

      # "15169 | 8.8.8.0/24 | US | arin |" for 8.8.8.8
      if ( $v->{'country'} ) {
        printf $v4_fh "%s %s|%s|%s|%s|\n", $n, $k, $n, $v->{'country'}, $v->{'rir'};
      }
      else {
        printf $v4_fh "%s %s|%s|%s|%s|\n", $n, $k, $n, 'UN', 'UN';
      }
    }
  }
  if ($v6) {
    foreach my $n ( @{ $v->{'nets_v6'} } ) {

      # "15169 | 8.8.8.0/24 | US | arin |" for 8.8.8.8
      if ( $v->{'country'} ) {
        printf $v6_fh "%s %s|%s|%s|%s|\n", $n, $k, $n, $v->{'country'}, $v->{'rir'};
      }
      else {
        printf $v6_fh "%s %s|%s|%s|%s|\n", $n, $k, $n, 'UN', 'UN';
      }
    }
  }
}

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
