#!/usr/bin/env perl

use 5.014;
use Getopt::Long;
use Pod::Usage;
use Time::Local;
use IO::Handle;
use warnings;
use strict;

# Optional dependency: NetAddr::IP for IP/CIDR map matching
my $has_netaddr_ip;

BEGIN {
    $has_netaddr_ip = eval {
        require NetAddr::IP;
        NetAddr::IP->import(qw(netlimit :lower));
        1;
    };
}

my $log_file  = "";
my $startTime = "";
my $endTime;
my $num_logs;
my $exclude_logs = 0;
my $man          = 0;
my $help         = 0;

# Associate file extensions with decompressors
my %decompressor = (
    'bz2' => [ 'bzip2', '-cd' ],
    'gz'  => [ 'gzip',  '-cd' ],
    'xz'  => [ 'xz',    '-cd' ],
    'zst' => [ 'zstd',  '-cd' ],
);

GetOptions(
    "log|l=s"          => \$log_file,
    "start=s"          => \$startTime,
    "end=s"            => \$endTime,
    "num-logs|n=i"     => \$num_logs,
    "exclude-logs|x=i" => \$exclude_logs,
    "help|?"           => \$help,
    "man"              => \$man
) or pod2usage(2);

pod2usage(1)                              if $help;
pod2usage( -exitval => 0, -verbose => 2 ) if $man;

# Global vars
my $rspamd_log;
my $log_file_num        = 1;
my $spinner_update_time = 0;

my %timeStamp;

#========================================

use JSON::PP;

my $multimap_ref = &configdump('multimap');
my %multimap     = %$multimap_ref;

die "No multimap configuration found in rspamadm configdump output.\n"
  unless %multimap;

# Track if we've warned about missing NetAddr::IP
my $netaddr_warning_shown = 0;

my %unmatched;

my %map;
my @symbols_search;    # Symbols defined in multimap to search in the log

for my $symbol ( keys %multimap ) {

    my @maps;

    if ( ref( $multimap{$symbol}{'map'} ) eq 'ARRAY' ) {
        @maps = @{ $multimap{$symbol}{'map'} };
    } else {
        @maps = ( $multimap{$symbol}{'map'} );
    }

    # Initialize structure for this symbol
    $map{$symbol} = {
        type      => $multimap{$symbol}{'type'},
        is_regexp => $multimap{$symbol}{'regexp'} ? 1 : 0,
        maps      => [],
    };

    my $has_valid_maps = 0;
    foreach my $map_source (@maps) {

        # Skip maps other than file maps:
        #    /path/to/list
        #    file:///path/to/list
        #    fallback+file:///path/to/list
        if ( $map_source =~ m{^.*(?<!file)://} ) {
            say "$symbol: $map_source [SKIPPED]";
            next;
        }

        my @map_entries = &get_map( $symbol, $map_source );
        if ( @map_entries == 0 ) {
            say "$symbol: $map_source [FAILED]";
            next;
        }

        # Count only non-comment entries
        my $entry_count = grep { !$_->{is_comment} } @map_entries;
        say "$symbol: $map_source [OK] - $entry_count entries";

        push @{ $map{$symbol}{maps} },
          {
            source  => $map_source,
            entries => \@map_entries,
          };

        $has_valid_maps = 1;
    }

    # Add symbol to search list only if it has valid file maps
    push @symbols_search, $symbol if $has_valid_maps;
}

die "No file-based multimap symbols found. Nothing to analyze.\n"
  unless @symbols_search;

say "====== maps added =====";

#========================================

foreach ( $startTime, $endTime ) { $_ = &normalized_time($_) }

if ( $log_file eq '-' || $log_file eq '' ) {
    $rspamd_log = \*STDIN;
    &ProcessLog();
} elsif ( -d "$log_file" ) {
    my $log_dir = "$log_file";

    my @logs = &GetLogfilesList($log_dir);

    # Process logs
    foreach (@logs) {
        my $ext = (/[^.]+\.?([^.]*?)$/)[0];
        my $dc  = $decompressor{$ext} || ['cat'];

        open( $rspamd_log, "-|", @$dc, "$log_dir/$_" )
          or die "cannot execute @$dc $log_dir/$_ : $!";

        printf { interactive(*STDERR) } "\033[J  Parsing log files: [%d/%d] %s\033[G", $log_file_num++, scalar @logs,
          $_;
        $spinner_update_time = 0;    # Force spinner update
        &spinner;

        &ProcessLog;

        close($rspamd_log)
          or warn "cannot close @$dc $log_dir/$_: $!";
    }
    print { interactive(*STDERR) } "\033[J\033[G";    # Progress indicator clean-up
} else {
    my $ext = ( $log_file =~ /[^.]+\.?([^.]*?)$/ )[0];
    my $dc  = $decompressor{$ext} || ['cat'];
    open( $rspamd_log, "-|", @$dc, $log_file )
      or die "cannot execute @$dc $log_file : $!";
    $spinner_update_time = 0;                         # Force spinner update
    &spinner;
    &ProcessLog();
}

#========================================
for my $symbol (@symbols_search) {

    say "$symbol:";
    say "    type=$map{$symbol}{type}";

    foreach my $map_entry ( @{ $map{$symbol}{maps} } ) {
        say "\nMap: $map_entry->{source}";
        say "Pattern\t\t\tMatches\t\tComment";
        say '-' x 80;

        foreach my $entry ( @{ $map_entry->{entries} } ) {

            # Output full-line comments as-is
            if ( $entry->{is_comment} ) {
                say $entry->{content};
                next;
            }

            # Output pattern
            if ( $map{$symbol}{is_regexp} ) {
                printf "%-23s", "/$entry->{pattern}/$entry->{flag}";
            } else {
                printf "%-23s", $entry->{pattern};
            }

            # Output match count
            if ( defined $entry->{count} && $entry->{count} > 0 ) {
                printf "\t%d", $entry->{count};
            } else {
                print "\t-";
            }

            # Output inline comment if present
            if ( $entry->{comment} ) {
                print "\t\t# $entry->{comment}";
            }

            say '';
        }
    }

    say '=' x 80;
}

if (%unmatched) {
    say "\nSymbols with unmatched values:";
    say '-' x 80;

    # Group by symbol name
    my %grouped;
    for my $key ( keys %unmatched ) {
        if ( $key =~ /^(\w+)\(/ ) {
            push @{ $grouped{$1} }, { full => $key, count => $unmatched{$key} };
        }
    }

    for my $symbol ( sort keys %grouped ) {
        my @entries = sort { $b->{count} <=> $a->{count} } @{ $grouped{$symbol} };
        say "\n$symbol: ${\(scalar @entries)} unmatched value(s)";
        for my $entry ( @entries[ 0 .. ( $#entries < 4 ? $#entries : 4 ) ] ) {
            say "  $entry->{count}x: $entry->{full}";
        }
        say "  ..." if @entries > 5;
    }
}

beep();

exit;

#-------------
# Subroutines
#-------------

sub configdump {
    my $cmd  = 'rspamadm configdump -C' . ( defined $_[0] ? " $_[0]" : '' );
    my $json = `$cmd`;

    # Check command execution status
    if ( $? != 0 ) {
        my $exit_code = $? >> 8;
        die "rspamadm configdump failed with exit code $exit_code\n";
    }

    # Check if we got any output
    die "rspamadm configdump returned empty output\n"
      unless ( defined $json && $json ne '' );

    # Try to decode JSON
    my $config;
    eval { $config = decode_json $json; };
    die "Failed to parse JSON from rspamadm configdump: $@\n" if $@;

    return $config;
}

sub beep {
    my $i = 0;
    $| = 1; while ($i++ <= 2) {print "\a"; system("sleep .12");}; print "\a"; $| = 0;
}

sub get_map {
    my ( $symbol, $map_file ) = @_;

    unless ( -e $map_file ) {
        warn "Map file does not exist: $map_file\n";
        return ();
    }

    unless ( -r $map_file ) {
        warn "Map file is not readable: $map_file\n";
        return ();
    }

    open( my $map_fh, '<', $map_file ) or die "Cannot open map file $map_file: $!\n";

    my @entries;
    while (<$map_fh>) {
        my $line_num = $.;
        chomp;

        # Full-line comments or empty lines
        if ( /^#(.*)$/ || /^\s*$/ ) {
            push @entries,
              {
                line_num   => $line_num,
                is_comment => 1,
                content    => $_,
              };
            next;
        }

        if ( $multimap{$symbol}{'regexp'} ) {

            # /pattern/flags [score] [# comment]
            my ( $pattern, $flags, $score, $comment ) = /^\/(.+)\/(\S?)(?:\s+(\d+\.?\d*))?(?:\s+#\s*(.*))?$/;

            die "Syntax error in $map_file at line $line_num\n" unless defined $pattern;

            $flags ||= '';

            # Validate flags: check that flags are valid for Rspamd
            die "Invalid regex flag in $map_file at line $line_num: '$flags' (supported: imsxurOL)\n"
              if $flags && $flags =~ /[^imsxurOL]/;

            # Extract only Perl-compatible PCRE flags for compilation.
            # Flags 'u', 'r', 'O', 'L' are Rspamd-specific flags that Perl doesn't support.
            # They affect processing in Rspamd, but not pattern matching in this utility context.
            my $perl_flags = $flags;
            $perl_flags =~ s/[^imsx]//g;

            # Precompile regex for performance and validation
            my $compiled = eval { qr/(?$perl_flags:$pattern)/ };
            die "Invalid regex in $map_file at line $line_num: $@\n" if $@;

            push @entries,
              {
                line_num => $line_num,
                pattern  => $pattern,
                flag     => $flags,
                compiled => $compiled,
                result   => $score,
                comment  => $comment,
                count    => 0,
              };
        } else {

            # Plain pattern [score] [# comment]
            # Pattern can be: IP, CIDR, domain, hostname, string, etc.
            my ( $pattern, $score, $comment ) = /^(\S+)(?:\s+(\d+\.?\d*))?(?:\s+#\s*(.*))?$/;

            die "Syntax error in $map_file at line $line_num\n" unless defined $pattern;

            push @entries,
              {
                line_num => $line_num,
                pattern  => $pattern,
                result   => $score,
                comment  => $comment,
                count    => 0,
              };
        }
    }

    close($map_fh) or warn "Cannot close map file $map_file: $!\n";

    return @entries;
}

sub ProcessLog {
    my ( $ts_format, @line ) = &log_time_format($rspamd_log);

    while () {
        last if eof $rspamd_log;
        $_ = (@line) ? shift @line : <$rspamd_log>;

        if (/^.*rspamd_task_write_log.*$/) {
            &spinner;
            my $ts;
            if ( $ts_format eq 'syslog' ) {
                $ts = syslog2iso( join ' ', ( split /\s+/ )[ 0 .. 2 ] );
            } elsif ( $ts_format eq 'syslog5424' ) {
                /^([0-9-]+)T([0-9:]+)/;
                $ts = "$1 $2";
            } else {
                $ts = join ' ', ( split /\s+/ )[ 0 .. 1 ];
            }

            next if ( $ts lt $startTime );
            next if ( defined $endTime && $ts gt $endTime );

            if ( $_ !~
                /\(([^()]+)\): \[(NaN|-?\d+(?:\.\d+)?)\/(-?\d+(?:\.\d+)?)\]\s+\[([^\]]*)\].+? time: (\d+\.\d+)ms/ )
            {
                warn "Bad log line: $_";
                next;
            }

            next
              if $4 eq '';

            my @symbols = split ',', $4;

            if ( defined( $timeStamp{'end'} ) ) {
                $timeStamp{'end'} = $ts if ( $ts gt $timeStamp{'end'} );
            } else {
                $timeStamp{'end'} = $ts;
            }

            if ( defined( $timeStamp{'start'} ) ) {
                $timeStamp{'start'} = $ts if ( $ts lt $timeStamp{'start'} );
            } else {
                $timeStamp{'start'} = $ts;
            }

            foreach my $s (@symbols_search) {
                my @selected = grep /$s/, @symbols;
                next
                  unless ( scalar(@selected) > 0 );

                foreach my $sym (@selected) {
                    my ( $sym_name, $sym_opt, $ip );
                    if ( $sym =~ /([^(]+)\([.0-9]+\)\{([^;]+);\}/ ) {
                        $sym_name = $1;
                        $sym_opt  = $2;
                        if ( $map{$sym_name}{type} eq 'ip' ) {
                            unless ($has_netaddr_ip) {
                                unless ($netaddr_warning_shown) {
                                    warn "\nSkipping IP map matching: NetAddr::IP module not installed\n";
                                    warn "Install with:\n";
                                    warn "  Debian/Ubuntu: apt-get install libnetaddr-ip-perl\n";
                                    warn "  FreeBSD:       pkg install p5-NetAddr-IP\n";
                                    warn "  RHEL/CentOS:   yum install perl-NetAddr-IP\n";
                                    warn "  CPAN:          cpan NetAddr::IP\n\n";
                                    $netaddr_warning_shown = 1;
                                }
                                next;
                            }
                            $ip = NetAddr::IP->new($sym_opt);
                            unless ( defined $ip ) {
                                warn "Invalid IP address in symbol $sym_name: $sym_opt\n";
                                next;
                            }
                        }
                    } else {
                        warn "Invalid symbol format: $sym\n";
                        $unmatched{$sym}++;
                        next;
                    }

                    my $matched = 0;

                    # Iterate through all maps for this symbol
                    foreach my $map_entry ( @{ $map{$sym_name}{maps} } ) {
                        foreach my $entry ( @{ $map_entry->{entries} } ) {

                            # Skip comments and empty lines
                            next if $entry->{is_comment};

                            if ( $map{$sym_name}{type} eq 'ip' ) {

                                # IP matching requires NetAddr::IP (checked above)
                                if ( $ip && $ip->within( NetAddr::IP->new( $entry->{pattern} ) ) ) {
                                    $entry->{count}++;
                                    $matched = 1;
                                    last;
                                }
                            } elsif ( $map{$sym_name}{is_regexp} ) {
                                if ( $sym_opt =~ $entry->{compiled} ) {
                                    $entry->{count}++;
                                    $matched = 1;
                                    last;
                                }
                            } else {
                                if ( $sym_opt eq $entry->{pattern} ) {
                                    $entry->{count}++;
                                    $matched = 1;
                                    last;
                                }
                            }
                        }
                        last if $matched;
                    }

                    $unmatched{$sym}++
                      unless $matched;
                }
            }
        }
    }
}

#========================================

# Common subroutines

sub GetLogfilesList {
    my ($dir) = @_;

    die "Log directory does not exist: $dir\n"
      unless -d $dir;
    die "Log directory is not readable: $dir\n"
      unless -r $dir;

    opendir( my $dir_fh, $dir ) or die "Cannot open directory $dir: $!\n";

    my $pattern = join( '|', keys %decompressor );
    my $re      = qr/\.[0-9]+(?:\.(?:$pattern))?/;

    # Add unnumbered logs first
    my @logs =
      grep { -f "$dir/$_" && !/$re/ } readdir($dir_fh);

    # Add numbered logs
    rewinddir($dir_fh);
    push( @logs, ( sort numeric ( grep { -f "$dir/$_" && /$re/ } readdir($dir_fh) ) ) );

    closedir($dir_fh);

    # Select required logs and revers their order
    @logs =
      reverse splice( @logs, $exclude_logs, $num_logs ||= @logs - $exclude_logs );

    die "No log files found in directory: $dir\n"
      unless @logs;

    # Loop through array printing out filenames
    print { interactive(*STDERR) } "\nLog files to process:\n";
    foreach my $file (@logs) {
        print { interactive(*STDERR) } "  $file\n";
    }
    print { interactive(*STDERR) } "\n";

    return @logs;
}

sub log_time_format {
    my $fh = shift;
    my ( $format, $line );
    while (<$fh>) {
        $line = $_;

        # 2017-08-08 00:00:01 #66984(
        # 2017-08-08 00:00:01.001 #66984(
        if (/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(\.\d{3})? #\d+\(/) {
            $format = 'rspamd';
            last;
        }

        # Aug  8 00:02:50 #66986(
        elsif (/^\w{3} (?:\s?\d|\d\d) \d\d:\d\d:\d\d #\d+\(/) {
            $format = 'syslog';
            last;
        }

        # Aug  8 00:02:50 hostname rspamd[66986]
        elsif (/^\w{3} (?:\s?\d|\d\d) \d\d:\d\d:\d\d \S+ rspamd\[\d+\]/) {
            $format = 'syslog';
            last;
        }

        # 2018-04-16T06:25:46.012590+02:00 rspamd rspamd[12968]
        elsif (/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[-+]\d{2}:\d{2}) \S+ rspamd\[\d+\]/) {
            $format = 'syslog5424';
            last;
        }

        # Skip newsyslog messages
        # Aug  8 00:00:00 hostname newsyslog[63284]: logfile turned over
        elsif (/^\w{3} (?:\s?\d|\d\d) \d\d:\d\d:\d\d\ \S+ newsyslog\[\d+\]: logfile turned over$/) {
            next;
        }

        # Skip journalctl messages
        # -- Logs begin at Mon 2018-01-15 11:16:24 MSK, end at Fri 2018-04-27 09:10:30 MSK. --
        elsif (
/^-- Logs begin at \w{3} \d{4}-\d\d-\d\d \d\d:\d\d:\d\d [A-Z]{3}, end at \w{3} \d{4}-\d\d-\d\d \d\d:\d\d:\d\d [A-Z]{3}\. --$/
          )
        {
            next;
        } else {
            die "Unknown log format\n";
        }
    }
    return ( $format, $line );
}

sub normalized_time {
    return
      if !defined( $_ = shift );

    /^\d\d(?::\d\d){0,2}$/
      ? sprintf '%04d-%02d-%02d %s', 1900 + (localtime)[5], 1 + (localtime)[4], (localtime)[3], $_
      : $_;
}

sub numeric {
    $a =~ /\.(\d+)\./;
    my $a_num = $1;
    $b =~ /\.(\d+)\./;
    my $b_num = $1;

    $a_num <=> $b_num;
}

sub spinner {
    my @spinner = qw{/ - \ |};
    return
      if ( ( time - $spinner_update_time ) < 1 );
    $spinner_update_time = time;
    printf { interactive(*STDERR) } "%s\r", $spinner[ $spinner_update_time % @spinner ];
    select()->flush();
}

# Convert syslog timestamp to "ISO 8601 like" format
# using current year as syslog does not record the year (nor the timezone)
# or the last year if the guessed time is in the future.
sub syslog2iso {
    my %month_map;
    @month_map{qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)} = 0 .. 11;

    my ( $month, @t ) = $_[0] =~ m/^(\w{3}) \s\s? (\d\d?) \s (\d\d):(\d\d):(\d\d)/x;
    my $epoch =
      timelocal( ( reverse @t ), $month_map{$month}, 1900 + (localtime)[5] );
    sprintf '%04d-%02d-%02d %02d:%02d:%02d', 1900 + (localtime)[5] - ( $epoch > time ), $month_map{$month} + 1, @t;
}

### Imported from IO::Interactive 1.022 Perl module
sub is_interactive {
    ## no critic (ProhibitInteractiveTest)

    my ($out_handle) = ( @_, select );    # Default to default output handle

    # Not interactive if output is not to terminal...
    return 0 if not -t $out_handle;

    # If *ARGV is opened, we're interactive if...
    if ( tied(*ARGV) or defined( fileno(ARGV) ) ) {    # this is what 'Scalar::Util::openhandle *ARGV' boils down to

        # ...it's currently opened to the magic '-' file
        return -t *STDIN if defined $ARGV && $ARGV eq '-';

        # ...it's at end-of-file and the next file is the magic '-' file
        return @ARGV > 0 && $ARGV[0] eq '-' && -t *STDIN if eof *ARGV;

        # ...it's directly attached to the terminal
        return -t *ARGV;
    }

    # If *ARGV isn't opened, it will be interactive if *STDIN is attached
    # to a terminal.
    else {
        return -t *STDIN;
    }
}

### Imported from IO::Interactive 1.022 Perl module
local ( *DEV_NULL, *DEV_NULL2 );
my $dev_null;

BEGIN {
    pipe *DEV_NULL, *DEV_NULL2
      or die "Internal error: can't create null filehandle";
    $dev_null = \*DEV_NULL;
}

### Imported from IO::Interactive 1.022 Perl module
sub interactive {
    my ($out_handle) = ( @_, \*STDOUT );    # Default to STDOUT
    return &is_interactive ? $out_handle : $dev_null;
}

__END__


=head1 NAME

rspamd-multimap-stats - count Rspamd maps matches by parsing log files

=head1 SYNOPSIS

rspamd-multimap-stats [options] [--log file]

 Options:
   --log=file             log file or directory to read (stdin by default)
   --start                starting time (oldest) for log parsing
   --end                  ending time (newest) for log parsing
   --num-logs=integer     number of recent logfiles to analyze (all files in the directory by default)
   --exclude-logs=integer number of latest logs to exclude (0 by default)
   --help                 brief help message
   --man                  full documentation

=head1 OPTIONS

=over 8

=item B<--log>

Specifies log file or directory to read data from. If a directory is specified B<rspamd-multimap-stats> analyses files
in the directory including known compressed file types. Number of log files can be limited using B<--num-logs> and
B<--exclude-logs> options. This assumes that files in the log directory have B<newsyslog(8)>- or B<logrotate(8)>-like
name format with numeric indexes. Files without indexes (generally it is merely one file) are considered the most
recent and files with lower indexes are considered newer.

=item B<--num-logs>

If set, limits number of analyzed logfiles in the directory to the specified value.

=item B<--exclude-logs>

Number of latest logs to exclude (0 by default).

=item B<--start>

Select log entries after this time. Format: C<YYYY-MM-DD HH:MM:SS> (can be truncated to any desired accuracy). If used
with B<--end> select entries between B<--start> and B<--end>. The omitted date defaults to the current date if you
supply the time.

=item B<--end>

Select log entries before this time. Format: C<YYYY-MM-DD HH:MM:SS> (can be truncated to any desired accuracy). If used
with B<--start> select entries between B<--start> and B<--end>. The omitted date defaults to the current date if you
supply the time.

=item B<--help>

Print a brief help message and exits.

=item B<--man>

Prints the manual page and exits.

=back

=head1 DESCRIPTION

B<rspamd-multimap-stats> will get maps from multimap module configuration, read the given Rspamd log file (or standard
input) and provide statistics on map matches.

Only file maps are supported for now. Examples of valid file map paths:     /path/to/list     file:///path/to/list   
fallback+file:///path/to/list

=head2 REGEX FLAGS SUPPORT

For regexp-type maps, the following PCRE regex flags are supported:

=over 4

=item B<i>

Case-insensitive matching (PCRE_CASELESS)

=item B<m>

Multiline mode - ^ and $ match line boundaries (PCRE_MULTILINE). Note: has no effect on single-line log values.

=item B<s>

Dotall mode - . matches newlines (PCRE_DOTALL). Note: has no effect on single-line log values.

=item B<x>

Extended mode - ignore whitespace and allow comments in pattern (PCRE_EXTENDED)

=item B<u>

UTF-8 mode (Rspamd-specific flag, noted but not affecting Perl matching)

=item B<r>

Raw mode (Rspamd-specific flag, noted but not affecting Perl matching)

=item B<O>

No optimization (Rspamd-specific flag, noted but not affecting Perl matching)

=item B<L>

Leftmost match for Hyperscan (Rspamd-specific flag, noted but not affecting Perl matching)

=back

Rspamd-specific flags (u, r, O, L) are validated and stored but do not affect pattern matching in this utility, as log
entries already contain matched values processed by Rspamd.

=cut

=head1 REQUIREMENTS

=over 4

=item *

Perl 5.14 or later

=item *

Perl modules: JSON::PP (core module)

=item *

Optional: NetAddr::IP (required only for C<type=ip> maps)

Install with: C<apt-get install libnetaddr-ip-perl> (Debian/Ubuntu), C<pkg install p5-NetAddr-IP> (FreeBSD), C<yum
install perl-NetAddr-IP> (RHEL/CentOS), or C<cpan NetAddr::IP>

=back
