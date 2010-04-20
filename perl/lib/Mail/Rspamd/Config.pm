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
use constant PARSER_STATE_FACTORS => 7;
use constant PARSER_STATE_METRIC => 8;
use constant PARSER_STATE_VIEW => 9;
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
		workers	=> {},
		modules	=> {},
		classifiers	=> {},
		factors => {},
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
			}
			elsif ($lce eq 'metric') {
				$self->parser_state->state = PARSER_STATE_METRIC;
				$self->_get_attr(@attrs, 'name', 'name', 1);
			}
			elsif ($lce eq 'module') {
				$self->parser_state->state = PARSER_STATE_MODULE;
				$self->_get_attr(@attrs, 'name', 'name', 1);
			}
			elsif ($lce eq 'classifier') {
				$self->parser_state->state = PARSER_STATE_METRIC;
				$self->_get_attr(@attrs, 'type', 'type', 1);
			}
			elsif ($lce eq 'factors') {
				$self->{parser_state}->{state} = PARSER_STATE_FACTORS;
			}
			else {
				# Other element
				$self->{parser_state}->{element} = $lce;
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_MODULE) {
			my $lce = lc $element;
			if ($lce eq 'option') {
				$self->_get_attr(@attrs, 'name', 'option', 1);
			}
			else {
				$self->{parser_state}->{valid} = 0;
				$self->{error} = 'Invalid tag <' . $lce . '> in module section';
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_FACTORS) {
			my $lce = lc $element;
			if ($lce eq 'factor') {
				$self->_get_attr(@attrs, 'name', 'name', 1);
			}
		}
		elsif ($self->{parser_state}->{state} == PARSER_STATE_CLASSIFIER) {
			my $lce = lc $element;
			if ($lce eq 'statfile') {
				$self->{parser_state}->{state} = PARSER_STATE_STATFILE;
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
	}
}

=head2 _handle_text

private _handle_text($parser, $string)

Description:
Handle data of xml tag

=cut
sub _handle_text {
	my ($self, $parser, $string) = @_;

	if ($self->{parser_state}->{valid}) {
		if ($self->{parser_state}->{state} == PARSER_STATE_MAIN) {
			if (defined ($string)) {
				chomp $string;
				if ($string) {
					$self->{ $self->{parser_state}->{element} } = $string;
				}
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

	foreach (@attrs) {
		if (lc $_ eq $name) {
			$self->parser_state->{$hash_name} = lc shift;
			$found = 1;
			last;
		}
		else {
			# Shift value
			shift;
		}
	}

	if (!$found && $required) {
		$self->{error} = "Attribute '$name' is required for tag $self->{element}";
		$self->parser_state->{'valid'} = 0;
	}
}
