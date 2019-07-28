#!/usr/bin/env perl
#

use warnings;
use strict;
use autodie;

use File::Basename;
use File::Fetch;
use Getopt::Long;
use Pod::Usage;

use FindBin;
use lib "$FindBin::Bin/extlib/lib/perl5";

use URI;

my %config = (
  asn_sources => [
    'ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest',
    'ftp://ftp.ripe.net/ripe/stats/delegated-ripencc-latest',
    'http://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest',
    'ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest',
    'ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest'
  ],
  bgp_sources => ['http://data.ris.ripe.net/rrc00/latest-bview.gz']
);

my $download_asn        = 0;
my $download_bgp        = 0;
my $download_target     = "./";
my $help                = 0;
my $man                 = 0;
my $v4                  = 1;
my $v6                  = 1;
my $parse               = 1;
my $v4_zone             = "asn.rspamd.com";
my $v6_zone             = "asn6.rspamd.com";
my $v4_file             = "asn.zone";
my $v6_file             = "asn6.zone";
my $ns_servers          = [ "asn-ns.rspamd.com", "asn-ns2.rspamd.com" ];
my $unknown_placeholder = "--";

GetOptions(
  "download-asn" => \$download_asn,
  "download-bgp" => \$download_bgp,
  "4!"           => \$v4,
  "6!"           => \$v6,
  "parse!"       => \$parse,
  "target=s"     => \$download_target,
  "zone-v4=s"    => \$v4_zone,
  "zone-v6=s"    => \$v6_zone,
  "file-v4=s"    => \$v4_file,
  "file-v6=s"    => \$v6_file,
  "ns-server=s@" => \$ns_servers,
  "help|?"       => \$help,
  "man"          => \$man,
  "unknown-placeholder" => \$unknown_placeholder,
) or
  pod2usage(2);

pod2usage(1) if $help;
pod2usage(-exitval => 0, -verbose => 2) if $man;

if ($download_asn) {
    foreach my $u (@{ $config{'asn_sources'} }) {
        download_file($u);
    }
}

if ($download_bgp) {
    foreach my $u (@{ $config{'bgp_sources'} }) {
        download_file($u);
    }
}

if (!$parse) {
    exit 0;
}

# Prefix to ASN map
my $networks = { 4 => {}, 6 => {} };

foreach my $u (@{ $config{'bgp_sources'} }) {
    my $parsed = URI->new($u);
    my $fname  = $download_target . '/' . basename($parsed->path);

    use constant {
      F_MARKER    => 0,
      F_TIMESTAMP => 1,
      F_PEER_IP   => 3,
      F_PEER_AS   => 4,
      F_PREFIX    => 5,
      F_AS_PATH   => 6,
      F_ORIGIN    => 7,
    };

    open(my $bgpd, '-|', "bgpdump -v -M $fname") or die "can't start bgpdump: $!";

    while (<$bgpd>) {
        chomp;
        my @e = split /\|/;
        if ($e[F_MARKER] ne 'TABLE_DUMP2') {
            warn "bad line: $_\n";
            next;
        }

        my $origin_as;
        my $prefix = $e[F_PREFIX];
        my $ip_ver = 6;

        if ($prefix =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/) {
            $ip_ver = 4;
        }

        if ($e[F_AS_PATH]) {

            # not empty AS_PATH
            my @as_path = split /\s/, $e[F_AS_PATH];
            $origin_as = pop @as_path;

            if (substr($origin_as, 0, 1) eq '{') {

                # route is aggregated
                if ($origin_as =~ /^{(\d+)}$/) {

                    # single AS aggregated, just remove { } around
                    $origin_as = $1;
                } else {

                    # use previous AS from AS_PATH
                    $origin_as = pop @as_path;
                }
            }

            # strip bogus AS
            while (is_bougus_asn($origin_as)) {
                $origin_as = pop @as_path;
                last if scalar @as_path == 0;
            }
        }

        # empty AS_PATH or all AS_PATH elements was stripped as bogus - use
        # PEER_AS as origin AS
        $origin_as //= $e[F_PEER_AS];

        $networks->{$ip_ver}{$prefix} = int($origin_as);
    }
}

# Remove default routes
delete $networks->{4}{'0.0.0.0/0'};
delete $networks->{6}{'::/0'};

# Now roughly detect countries
my $as_info = {};

# RIR statistics exchange format
# https://www.apnic.net/publications/media-library/documents/resource-guidelines/rir-statistics-exchange-format
# https://www.arin.net/knowledge/statistics/nro_extended_stats_format.pdf
# first 7 fields for this two formats are same
use constant {
  F_REGISTRY => 0,  # {afrinic,apnic,arin,iana,lacnic,ripencc}
  F_CC       => 1,  # ISO 3166 2-letter contry code
  F_TYPE     => 2,  # {asn,ipv4,ipv6}
  F_START    => 3,
  F_VALUE    => 4,
  F_DATE     => 5,
  F_STATUS   => 6,
};

foreach my $u (@{ $config{'asn_sources'} }) {
    my $parsed = URI->new($u);
    my $fname  = $download_target . '/' . basename($parsed->path);
    open(my $fh, "<", $fname) or die "Cannot open $fname: $!";

    while (<$fh>) {
        next if /^\#/;
        chomp;
        my @elts = split /\|/;

        if ($elts[F_TYPE] eq 'asn' && $elts[F_START] ne '*') {
            my $as_start = int($elts[F_START]);
            my $as_end   = $as_start + int($elts[F_VALUE]) - 1;

            for my $as ($as_start .. $as_end) {
                $as_info->{$as}{'country'} = $elts[F_CC];
                $as_info->{$as}{'rir'}     = $elts[F_REGISTRY];
            }
        }
    }
}

# Write zone files
my $ns_list     = join ' ', @{$ns_servers};
my $zone_header = << "EOH";
\$SOA 43200 $ns_servers->[0] support.rspamd.com 0 600 300 86400 300
\$NS  43200 $ns_list
EOH

if ($v4) {
    # create temp file in the same dir so we can be sure that mv is atomic
    my $out_dir = dirname($v4_file);
    my $out_file = basename($v4_file);
    my $temp_file = "$out_dir/.$out_file.tmp";
    open my $v4_fh, '>', $temp_file;
    print $v4_fh $zone_header;

    while (my ($net, $asn) = each %{ $networks->{4} }) {
        my $country = $as_info->{$asn}{'country'} || $unknown_placeholder;
        my $rir     = $as_info->{$asn}{'rir'}     || $unknown_placeholder;

        # "15169|8.8.8.0/24|US|arin|" for 8.8.8.8
        printf $v4_fh "%s %s|%s|%s|%s|\n", $net, $asn, $net, $country, $rir;
    }

    close $v4_fh;
    rename $temp_file, $v4_file;
}

if ($v6) {
    my $out_dir = dirname($v6_file);
    my $out_file = basename($v6_file);
    my $temp_file = "$out_dir/.$out_file.tmp";
    open my $v6_fh, '>', $temp_file;
    print $v6_fh $zone_header;

    while (my ($net, $asn) = each %{ $networks->{6} }) {
        my $country = $as_info->{$asn}{'country'} || $unknown_placeholder;
        my $rir     = $as_info->{$asn}{'rir'}     || $unknown_placeholder;

        # "2606:4700:4700::/48 13335|2606:4700:4700::/48|US|arin|" for 2606:4700:4700::1111
        printf $v6_fh "%s %s|%s|%s|%s|\n", $net, $asn, $net, $country, $rir;
    }

    close $v6_fh;
    rename $temp_file, $v6_file;
}

exit 0;

########################################################################

sub download_file {
    my ($url) = @_;

    local $File::Fetch::WARN    = 0;
    local $File::Fetch::TIMEOUT = 180;  # connectivity to ftp.lacnic.net is bad

    my $ff    = File::Fetch->new(uri => $url);
    my $where = $ff->fetch(to => $download_target) or
      die "$url: ", $ff->error;

    return $where;
}

# Returns true if AS number is bogus
# e. g. a private AS.
# List of allocated and reserved AS:
# https://www.iana.org/assignments/as-numbers/as-numbers.txt
sub is_bougus_asn {
    my $as = shift;

    # 64496-64511  Reserved for use in documentation and sample code
    # 64512-65534  Designated for private use
    # 65535        Reserved
    # 65536-65551  Reserved for use in documentation and sample code
    # 65552-131071 Reserved
    return 1 if $as >= 64496 && $as <= 131071;

    # Reserved (RFC6996, RFC7300, RFC7607)
    return 1 if $as == 0 || $as >= 4200000000;

    return 0;
}

__END__

=head1 NAME

asn.pl - download and parse ASN data for Rspamd

=head1 SYNOPSIS

asn.pl [options]

 Options:
   --download-asn         Download ASN data from RIRs
   --download-bgp         Download BGP full view dump from RIPE RIS
   --target               Where to download files (default: current dir)
   --zone-v4              IPv4 zone (default: asn.rspamd.com)
   --zone-v6              IPv6 zone (default: asn6.rspamd.com)
   --file-v4              IPv4 zone file (default: ./asn.zone)
   --file-v6              IPv6 zone (default: ./asn6.zone)
   --unknown-placeholder  Placeholder for unknown elements (default: --)
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

# vim: et:ts=4:sw=4