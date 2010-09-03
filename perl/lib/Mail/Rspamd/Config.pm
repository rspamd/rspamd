=head1 NAME

Mail::Rspamd::Config - Utilities for rspamd configuration

=head1 SYNOPSIS

=head1 DESCRIPTION

Mail::Rspamd::Config is a module that provides a perl implementation for
configuring rspamd.

=cut

package Mail::Rspamd::Config;

use Carp;
use XML::Parser;

use vars qw($VERSION);
$VERSION = "1.02";

use constant PARSER_STATE_START => 0;
use constant PARSER_STATE_MAIN => 1;
use constant PARSER_STATE_WORKER => 2;
use constant PARSER_STATE_MODULE => 3;
use constant PARSER_STATE_CLASSIFIER => 4;
use constant PARSER_STATE_STATFILE => 5;
use constant PARSER_STATE_LOGGING => 6;
use constant PARSER_STATE_METRIC => 8;
use constant PARSER_STATE_VIEW => 9;
use constant PARSER_STATE_MODULES => 10;
use constant PARSER_STATE_END => -1;


=head1 PUBLIC METHODS

=head2 new

public class (Mail::Rspamd::Config) new (\% $args)

Description:
This method creates a new Mail::Rspamd::Config object.

=cut

sub new {
	my ($class, $args) = @_;

	$class = ref($class) || $class;

	my $self = {
		workers	=> [],
		modules	=> {},
		classifiers	=> {},
		metrics => {},
		options => {},
		variables => {},
		logging	=> {},
		lua => [],
		composites => {},
		paths => [],
		views => [],
		parser_state => {
			state => PARSER_STATE_START,
			valid => 1,
		},
	};
	
	if (defined ($args->{'file'})) {
		$self->{'file'} = $args->{'file'}
	}


	bless($self, $class);

	$self;
}

=head2 load

public load (String $file)

Description:
Loads rspamd config file and parses it.

=cut

sub load {
	my ($self, $file) = @_;

	if (defined ($file)) {
		$self->{'file'} = $file;
	}

	if (!defined ($self->{'file'}) || ! -f $self->{'file'}) {
		carp 'cannot open file specified';
		return undef;
	}

	my $parser = new XML::Parser(Handlers => {Start => sub { $self->_handle_start_element(@_) },
                                     End   => sub { $self->_handle_end_element(@_) },
                                     Char  => sub { $self->_handle_text(@_) } });
	
	$parser->parsefile($self->{file});
}

=head2 save

public save (String $file)

Description:
Dumps rspamd config to xml file.

=cut

sub save {
	my ($self, $file) = @_;

	if (defined ($file)) {
		$self->{'file'} = $file;
	}

	if (!defined ($self->{'file'})) {
		carp 'cannot open file specified';
		return undef;
	}
	
	$self->_dump();
}

=head2 _handle_start_element

private _handle_start_element($parser, $element, [attr, value...])

Description:
Handle start xml tag of rspamd

=cut
sub _handle_start_element {
	my ($self, $parser, $element, @attrs) = @_;


	if ($self->{parser_state}->{valid}) {
		# Start element
		$self->{parser_state}->{element} = lc $element;

		if ($self->{parser_state}->{state} == PARSER_STATE_START) {
			if (lc $element eq 'rspamd') {
				$self->{parser_state}->{state} = PARSER_STATE_MAIN;
			}
			else {
				$self->{parser_state}->{valid} = 0;
				$self->{error} = 'Start element missing, it must be <rspamd>, but is <' . $element . '>';
			}
		}
		# Main section
		elsif ($self->{parser_state}->{state} == PARSER_STATE_MAIN) {
			my $lce = lc $element;
			if ($lce eq 'logging') {
				$self->{parser_state}->{state} = PARSER_STATE_LOGGING;
			}
			elsif ($lce eq 'worker') {
				$self->{parser_state}->{state} = PARSER_STATE_WORKER;
				$self->{parser_state}->{worker} = { options => {} };
			}
			elsif ($lce eq 'view') {
				$self->{parser_state}->{state} = PARSER_STATE_VIEW;
				$self->{parser_state}->{view} = {};
			}
			elsif ($lce eq 'metric') {
				$self->{parser_state}->{state} = PARSER_STATE_METRIC;
				$self->{parser_state}->{metric} = { symbols => {} };
			}
			elsif ($lce eq 'module') {
				$self->{parser_state}->{state} = PARSER_STATE_MODULE;
				$self->_get_attr('name', 'name', 1, @attrs);
				$self->{parser_state}->{module} = {};
			}
			elsif ($lce eq 'classifier') {
				$self->{parser_state}->{state} = PARSER_STATE_CLASSIFIER;
				$self->_get_attr('type', 'type', 1, @attrs);
				$self->{parser_state}->{classifier} = { statfiles => []};
			}
			elsif ($lce eq 'variable') {
				$self->_get_attr('name', 'name', 1, @attrs);
			}
			elsif ($lce eq 'lua') {
				$self->_get_attr('src', 'src', 1, @attrs);
			}
			elsif ($lce eq 'composite') {
				$self->_get_attr('name', 'name', 1, @attrs);
			}
			elsif ($lce eq 'modules') {
				$self->{parser_state}->{state} = PARSER_STATE_MODULES;
			}
			else {
				# Other element
				$self->{parser_state}->{element} = $lce;
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_MODULE) {
			my $lce = lc $element;
			if ($lce eq 'option') {
				$self->_get_attr('name', 'option', 1, @attrs);
			}
			else {
				$self->{parser_state}->{valid} = 0;
				$self->{error} = 'Invalid tag <' . $lce . '> in module section';
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_METRIC) {
			my $lce = lc $element;
			if ($lce eq 'symbol') {
				$self->_get_attr('weight', 'weight', 1, @attrs);
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_CLASSIFIER) {
			my $lce = lc $element;
			if ($lce eq 'statfile') {
				$self->{parser_state}->{state} = PARSER_STATE_STATFILE;
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_WORKER) {
			my $lce = lc $element;
			if ($lce eq 'param') {
				$self->_get_attr('name', 'name', 1, @attrs);
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_END) {
			# Tags after end element
			$self->{parser_state}->{valid} = 0;
			$self->{error} = 'Invalid tag <' . $element . '> after end tag';
		}
		else {
			# On other states just set element
		}
	}
}


=head2 _handle_end_element

private _handle_end_element($parser, $element)

Description:
Handle end xml tag of rspamd

=cut
sub _handle_end_element {
	my ($self, $parser, $element) = @_;

	if ($self->{parser_state}->{valid}) {
		my $lce = lc $element;
		if ($self->{parser_state}->{state} == PARSER_STATE_MAIN) {
			if ($lce eq 'rspamd') {
				$self->{parser_state}->{state} = PARSER_STATE_END;
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_WORKER) {
			if ($lce eq 'worker') {
				push(@{$self->{workers}}, $self->{parser_state}->{worker});
				$self->{parser_state}->{state} = PARSER_STATE_MAIN;
				$self->{parser_state}->{worker} = undef;
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_CLASSIFIER) {
			if ($lce eq 'classifier') {
				$self->{classifiers}->{ $self->{parser_state}->{type} } = $self->{parser_state}->{classifier};
				$self->{parser_state}->{state} = PARSER_STATE_MAIN;
				$self->{parser_state}->{classifier} = undef;
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_METRIC) {
			if ($lce eq 'metric') {
				if (exists ($self->{parser_state}->{metric}->{name})) {
					$self->{metrics}->{ $self->{parser_state}->{metric}->{name} } = $self->{parser_state}->{metric};
					$self->{parser_state}->{state} = PARSER_STATE_MAIN;
					$self->{parser_state}->{metric} = undef;
				}
				else {
					$self->{parser_state}->{valid} = 0;
					$self->{error} = 'Metric must have <name> tag';
				}
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_STATFILE) {
			if ($lce eq 'statfile') {
				push(@{$self->{parser_state}->{classifier}->{statfiles}}, $self->{parser_state}->{statfile});
				$self->{parser_state}->{state} = PARSER_STATE_CLASSIFIER;
				$self->{parser_state}->{statfile} = undef;
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_MODULE) {
			if ($lce eq 'module') {
				$self->{modules}->{ $self->{parser_state}->{name} } = $self->{parser_state}->{module};
				$self->{parser_state}->{state} = PARSER_STATE_MAIN;
				$self->{parser_state}->{module} = undef;
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_LOGGING) {
			if ($lce eq 'logging') {
				$self->{parser_state}->{state} = PARSER_STATE_MAIN;
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_VIEW) {
			if ($lce eq 'view') {
				push(@{$self->{views}}, $self->{parser_state}->{view});
				$self->{parser_state}->{state} = PARSER_STATE_MAIN;
				$self->{parser_state}->{view} = undef;
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_MODULES) {
			if ($lce eq 'modules') {
				$self->{parser_state}->{state} = PARSER_STATE_MAIN;
			}
		}
	}
}

=head2 _handle_text

private _handle_text($parser, $string)

Description:
Handle data of xml tag

=cut
sub _handle_text {
	my ($self, $parser, $string) = @_;
	
	my $data;

	if (defined ($string) && $string =~ /^\s*(\S*(?:\s+\S+)*)\s*$/) {
		$data = $1;
	}
	else {
		return undef;
	}
	if (!$data) {
		return undef;
	}

	if ($self->{parser_state}->{valid}) {
		if ($self->{parser_state}->{state} == PARSER_STATE_MAIN) {
			if ($self->{parser_state}->{element} eq 'variable') {
				$self->{variables}->{ $self->{parser_state}->{name} } = $data;
			}
			elsif ($self->{parser_state}->{element} eq 'composite') {
				$self->{composites}->{ $self->{parser_state}->{name} } = $data;
			}
			elsif ($self->{parser_state}->{element} eq 'lua') {
				push(@{$self->{lua}}, $self->{parser_state}->{src});
			}
			else {
				$self->{options}->{ $self->{parser_state}->{element} } = $data;
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_LOGGING) {
			$self->{logging}->{ $self->{parser_state}->{element} } = $data;
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_WORKER) {
			if ($self->{parser_state}->{element} eq 'param' || $self->{parser_state}->{element} eq 'option') {
				$self->{parser_state}->{worker}->{options}->{$self->{parser_state}->{name}} = $data;
			}
			else {
				$self->{parser_state}->{worker}->{ $self->{parser_state}->{element} } = $data;
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_CLASSIFIER) {
			$self->{parser_state}->{classifier}->{ $self->{parser_state}->{element} } = $data;
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_STATFILE) {
			$self->{parser_state}->{statfile}->{ $self->{parser_state}->{element} } = $data;
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_MODULE) {
			$self->{parser_state}->{module}->{ $self->{parser_state}->{option} } = $data;
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_VIEW) {
			$self->{parser_state}->{view}->{ $self->{parser_state}->{option} } = $data;
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_MODULES) {
			push(@{$self->{paths}}, $data);
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_METRIC) {
			if ($self->{parser_state}->{element} eq 'symbol') {
				$self->{parser_state}->{metric}->{symbols}->{ $data } = $self->{parser_state}->{weight};
			}
			else {
				$self->{parser_state}->{metric}->{ $self->{parser_state}->{element} } = $data;
			}
		}
	}
}

=head2 _get_attr

private _get_attr($name, $hash_name, $required, @attrs)

Description:
Extract specified attr and put it to parser_state

=cut
sub _get_attr {
	my ($self, $name, $hash_name, $required, @attrs) = @_;
	my $found = 0;
	my $param = 1;

	foreach (@attrs) {
		if ($found) {
			$self->{parser_state}->{$hash_name} = $_;
			last;
		}
		else {
			if ($param) {
				if (lc $_ eq $name) {
					$found = 1;
				}
				$param = 0;
			}
			else {
				$param = 1;
			}
		}
	}

	if (!$found && $required) {
		$self->{error} = "Attribute '$name' is required for tag '$self->{parser_state}->{element}'";
		$self->{parser_state}->{'valid'} = 0;
	}
}

=head2 _dump

private _dump()

Description:
Dumps rspamd config to xml file

=cut
sub _dump {
	my ($self) = @_;

	open(XML, "> $self->{file}") or carp "cannot open file '$self->file'";

	print XML "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<rspamd>\n";
	
	print XML "<!-- Main section -->\n";
	while(my ($k, $v) = each (%{$self->{options}})) {
		my $ek = $self->_xml_escape($k);
		print XML "<$ek>" . $self->_xml_escape($v) . "</$ek>\n";
	}
	foreach my $lua(@{$self->{lua}}) {
		print XML "<lua src=\"". $self->_xml_escape($lua) ."\">lua</lua>\n";
	}
	print XML "<!-- End of main section -->\n\n";

	print XML "<!-- Variables section -->\n";
	while(my ($k, $v) = each (%{$self->{variables}})) {
		my $ek = $self->_xml_escape($k);
		print XML "<variable name=\"$ek\">" . $self->_xml_escape($v) . "</variable>\n";
	}
	print XML "<!-- End of variables section -->\n\n";

	print XML "<!-- Composites section -->\n";
	while(my ($k, $v) = each (%{$self->{composites}})) {
		my $ek = $self->_xml_escape($k);
		print XML "<composite name=\"$ek\">" . $self->_xml_escape($v) . "</composite>\n";
	}
	print XML "<!-- End of composites section -->\n\n";

	print XML "<!-- Workers section -->\n";
	foreach my $worker (@{$self->{workers}}) {
		print XML "<worker>\n";
		while (my ($k, $v) = each (%{$worker})) {
			my $ek = $self->_xml_escape($k);
			if ($k eq 'options') {
				while (my ($kk, $vv) = each (%{$v})) {
					print XML "  <param name=\"". $self->_xml_escape($kk) ."\">" . $self->_xml_escape($vv) . "</param>\n";
				}
			}
			else {
				print XML "  <$ek>" . $self->_xml_escape($v) . "</$ek>\n";
			}
		}
		print XML "</worker>\n";
	}
	print XML "<!-- End of workers section -->\n\n";

	print XML "<!-- Metrics section -->\n";
	while (my ($k, $v) = each (%{$self->{metrics}})) {
		print XML "<metric name=\"". $self->_xml_escape($k) ."\">\n";
		while (my ($kk, $vv) = each (%{ $v })) {
			my $ek = $self->_xml_escape($kk);
			if ($ek eq 'symbols') {
				while (my ($sym, $weight) = each (%{ $vv })) {
					print XML "  <symbol weight=\"". $self->_xml_escape($weight) ."\">" . $self->_xml_escape($sym) . "</symbol>\n";
				}
			}
			else {
				print XML "  <$ek>" . $self->_xml_escape($vv) . "</$ek>\n";
			}
		}
		print XML "</metric>\n";
	}
	print XML "<!-- End of metrics section -->\n\n";

	print XML "<!-- Logging section -->\n<logging>\n";
	while (my ($k, $v) = each (%{$self->{logging}})) {
		my $ek = $self->_xml_escape($k);
		print XML "  <$ek>" . $self->_xml_escape($v) . "</$ek>\n";
	}
	print XML "</logging>\n<!-- End of logging section -->\n\n";

	print XML "<!-- Classifiers section -->\n";
	while (my ($type, $classifier) = each(%{$self->{classifiers}})) {
		print XML "<classifier type=\"". $self->_xml_escape($type) ."\">\n";
		while (my ($k, $v) = each (%{$classifier})) {
			my $ek = $self->_xml_escape($k);
			if ($k eq 'statfiles') {
				foreach my $statfile (@{$v}) {
					print XML "  <statfile>\n";
					while (my ($kk, $vv) = each (%{$statfile})) {
						my $ekk = $self->_xml_escape($kk);
						print XML "    <$ekk>" . $self->_xml_escape($vv) . "</$ekk>\n";
					}
					print XML "  </statfile>\n";
				}
			}
			else {
				print XML "  <$ek>" . $self->_xml_escape($v) . "</$ek>\n";
			}
		}
		print XML "</classifier>\n";
	}
	print XML "<!-- End of classifiers section -->\n\n";

	print XML "<!-- Modules section -->\n";
	while (my ($name, $module) = each(%{$self->{modules}})) {
		print XML "<module name=\"". $self->_xml_escape($name) ."\">\n";
		while (my ($k, $v) = each (%{$module})) {
			my $ek = $self->_xml_escape($k);
			print XML "  <option name=\"$ek\">" . $self->_xml_escape($v) . "</option>\n";
		}
		print XML "</module>\n";
	}
	print XML "<!-- End of modules section -->\n\n";

	print XML "<!-- Paths section -->\n<modules>\n";
	foreach my $module(@{$self->{paths}}) {
		print XML "  <module>" . $self->_xml_escape($module) . "</module>\n";
	}
	print XML "</modules>\n<!-- End of paths section -->\n\n";

	print XML "</rspamd>\n";
}

=head2 _xml_escape

private _xml_escape()

Description:
Escapes characters in xml string

=cut
sub _xml_escape {
  my $data = $_[1];
  if ($data =~ /[\&\<\>\"]/) {
    $data =~ s/\&/\&amp\;/g;
    $data =~ s/\</\&lt\;/g;
    $data =~ s/\>/\&gt\;/g;
    $data =~ s/\"/\&quot\;/g;
  }
  return $data;
}

=head2 _xml_unescape

private _xml_unescape()

Description:
Unescapes characters in xml string

=cut
sub _xml_unescape {
  my $data = $_[1];
  if ($data =~ /\&amp|\&lt|\&gt|\&quot/) {
    $data =~ s/\&amp;/\&/g;
    $data =~ s/\&lt\;/\</g;
    $data =~ s/\&gt\;/\>/g;
    $data =~ s/\&quot\;/\"/g;
  }
  return $data;
}
