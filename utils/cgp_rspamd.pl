#!/usr/bin/env perl

use warnings;
use strict;
use JSON::XS;
use AnyEvent;
use AnyEvent::HTTP;
use AnyEvent::IO;
use EV;
use Pod::Usage;
use Getopt::Long;

my $rspamd_host = "localhost:11333";
my $man = 0;
my $help = 0;
my $local = 0;
my $header = "X-Spam: yes";
my $reject_message = "Spam message rejected";

GetOptions(
  "host=s" => \$rspamd_host,
  "header=s" => \$header,
  "reject-message=s" => \$reject_message,
  "help|?" => \$help,
  "man" => \$man
) or pod2usage(2);

pod2usage(1) if $help;
pod2usage(-exitval => 0, -verbose => 2) if $man;

my $scanned = 0;
# Turn off bufferization as required by CGP
$| = 1;

sub cgp_string {
  my ($in) = @_;

  $in =~ s/\"/\\"/;
  $in =~ s/\n/\\n/;
  $in =~ s/\r/\\r/;

  return "\"$in\"";
}

sub rspamd_scan {
  my ($tag, $file) = @_;

  my $http_callback = sub {
    my ($body, $hdr) = @_;

    if ($hdr->{Status} =~ /^2/) {
      my $js = decode_json($body);
      $scanned ++;

      if (!$js) {
        print "* Rspamd: Bad response for $file: invalid JSON: parse error\n";
        print "$tag FAILURE\n";
      }
      else {
        my $def = $js->{'default'};

        if (!$def) {
          print "* Rspamd: Bad response for $file: invalid JSON: default is missing\n";
          print "$tag FAILURE\n";
        }
        else {
          my $action = $def->{'action'};
          my $id = $js->{'message-id'};

          my $symbols = "";
          while (my ($k, $s) = each(%{$def})) {
            if (ref($s) eq "HASH" && $s->{'score'}) {
              $symbols .= sprintf "%s(%.2f);", $k, $s->{'score'};
            }
          }

          printf "* Rspamd: Scanned %s; id: <%s>; Score: %.2f / %.2f; Symbols: [%s]\n",
            $file, $id, $def->{'score'}, $def->{'required_score'}, $symbols;

          if ($action eq 'reject') {
            print "$tag ERROR " . cgp_string($reject_message) . "\n";
          }
          elsif ($action eq 'add header' || $action eq 'rewrite subject') {
            print "$tag ADDHEADER " . cgp_string($header) . " OK\n";
          }
          elsif ($action eq 'soft reject') {
            print "$tag REJECT Try again later\n";
          }
          else {
            print "$tag OK\n";
          }
        }
      }
    } else {
      print "* Rspamd: Bad response for $file: HTTP error: $hdr->{Status} $hdr->{Reason}\n";
      print "$tag FAILURE\n";
    }
  };

  if ($local) {
    # Use file scan
    # XXX: not implemented now due to CGP queue format
    http_get("http://$rspamd_host/symbols?file=$file", $http_callback);
  }
  else {
    aio_load($file, sub {
      my ($data) = @_ or return print "* Cannot open $file: $!\n$tag FAILURE\n";

      # Parse CGP format
      $data =~ s/^((?:[^\n]*\n)*?)\n(.*)$/$2/ms;
      my @envelope = split /\n/, $1;
      chomp(@envelope);
      my $from;
      my @rcpts;
      my $ip;

      foreach my $elt (@envelope) {
        if ($elt =~ /^P\s[^<]*(<[^>]*>).*$/) {
          $from = $1;
        }
        elsif ($elt =~ /^R\s[^<]*(<[^>]*>).*$/) {
          push @rcpts, $1;
        }
        elsif ($elt =~ /^S .*\[(.+)\]/) {
          $ip = $1;
        }
      }

      my $headers = {};
      if ($file =~ /\/([^\/.]+)\.msg$/) {
        $headers->{'Queue-ID'} = $1;
      }
      if ($from) {
        $headers->{From} = $from;
      }
      if (scalar(@rcpts) > 0) {
        # XXX: Anyevent cannot parse headers with multiple values
        foreach (@rcpts) {
          $headers->{Rcpt} = $_;
        }
      }
      if ($ip) {
        $headers->{IP} = $ip;
      }

      http_post("http://$rspamd_host/symbols", $data, headers => $headers, $http_callback);
    });
  }
}

# Show informational message
print "* Rspamd CGP filter has been started\n";

my $w = AnyEvent->io(
  fh => \*STDIN,
  poll => 'r', cb => sub {
    chomp (my $input = <STDIN>);

    if ($input =~ /^(\d+)\s+(\S+)(\s+(\S+)\s*)?$/) {
      my $tag = $1;
      my $cmd = $2;

      if ($cmd eq "INTF") {
        print "$input\n";
      }
      elsif ($cmd eq "FILE" && $4) {
        my $file = $4;
        print "* Scanning file $file\n";
        rspamd_scan $tag, $file;
      }
      elsif ($cmd eq "QUIT") {
        print "* Terminating after scanning of $scanned files\n";
        print "$tag OK\n";
        exit 0;
      }
    }
  }
);

EV::run;

__END__

=head1 NAME

cgp_rspamd - implements Rspamd filter for CommunigatePro MTA

=head1 SYNOPSIS

cgp_rspamd [options]

 Options:
   --host=hostport        Rspamd host to connect (localhost:11333 by default)
   --header               Add specific header for a spam message ("X-Spam: yes" by default)
   --reject-message       Rejection message for spam mail ("Spam message rejected" by default)
   --help                 brief help message
   --man                  full documentation

=head1 OPTIONS

=over 8

=item B<--host>

Specifies Rspamd host to use for scanning

=item B<--header>

Specifies the header that should be added when Rspamd action is B<add header>
or B<rewrite subject>.

=item B<--reject-message>

Specifies the rejection message for spam.

=item B<--help>

Print a brief help message and exits.

=item B<--man>

Prints the manual page and exits.

=back

=head1 DESCRIPTION

B<cgp_rspamd> is intended to scan messages processed with B<CommunigatePro> MTA
on some Rspamd scanner. It reads standard input and parses CGP helpers
protocol.  On scan requests, this filter can query Rspamd to process a message.
B<cgp_rspamd> can tell CGP to add header or reject SPAM messages depending on
Rspamd scan result.

=back

=cut
