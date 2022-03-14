#!/usr/bin/env perl
package YaraParse;
use parent 'Sugar::Lang::BaseSyntaxParser';
use strict;
use warnings;

use feature 'say';





##############################
##### variables and settings
##############################



our $tokens = [
	'string' => qr/"(?:[^"\\]|\\["\\rtn]|\\x[0-9a-fA-F]{2})*"/s,
	'identifier' => qr/[a-zA-Z_][a-zA-Z0-9_]*+/,
	'symbol' => qr/\$|\{|\}|\[|\]|,|:|=/,
	'hex_byte' => qr/[0-9a-fA-F?]{2}/,
	'number' => qr/-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][\+\-]?[0-9]+)?/,
	'whitespace' => qr/\s++/s,
];

our $ignored_tokens = [
	'whitespace',
];

our $contexts = {
	root => 'context_root',
	rule_set => 'context_rule_set',
	rule_block => 'context_rule_block',
	strings_block => 'context_strings_block',
	string_definition => 'context_string_definition',
	condition_block => 'context_condition_block',
	meta_block => 'context_meta_block',
};



##############################
##### api
##############################



sub new {
	my ($class, %opts) = @_;

	$opts{token_regexes} = $tokens;
	$opts{ignored_tokens} = $ignored_tokens;
	$opts{contexts} = $contexts;

	my $self = $class->SUPER::new(%opts);

	return $self
}

sub parse {
	my ($self, @args) = @_;
	return $self->SUPER::parse(@args)
}



##############################
##### sugar contexts functions
##############################

sub context_root {
	my ($self) = @_;
	my $context_value = [];
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected !rule_set', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and (($tokens[0] = $self->context_rule_set([])) and (($context_value = $tokens[0]) or do { 1 })));
	$save_tokens_index = $self->{tokens_index};
	return $context_value;
}
sub context_rule_set {
	my ($self, $context_value) = @_;
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected \'rule\', !rule_block', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and (do { my $save_tokens_index = $self->{tokens_index}; while (((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'rule' and (($tokens[1] = $self->context_rule_block) and do { push @$context_value, $tokens[1]; 1 })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }));
	return $context_value;
}
sub context_rule_block {
	my ($self, $context_value) = @_;
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected identifier token, \'{\', [ \'meta\', \':\', !meta_block ], \'strings\', \':\', !strings_block, \'condition\', \':\', !condition_block, \'}\' or ', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 7 <= @{$self->{tokens}}) and (($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[0] eq 'identifier' and do { $context_value->{identifier} = $tokens[0][1]; 1 }) and ($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '{' and (do { my $save_tokens_index = $self->{tokens_index}; if (((($self->{tokens_index} = $save_tokens_index) + 2 <= @{$self->{tokens}}) and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'meta' and ($tokens[3] = $self->{tokens}[$self->{tokens_index}++])->[1] eq ':' and (($tokens[4] = $self->context_meta_block({})) and do { $context_value->{meta} = $tokens[4]; 1 })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }) and ($tokens[3] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'strings' and ($tokens[4] = $self->{tokens}[$self->{tokens_index}++])->[1] eq ':' and (($tokens[5] = $self->context_strings_block([])) and do { $context_value->{strings} = $tokens[5]; 1 }) and ($tokens[6] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'condition' and ($tokens[7] = $self->{tokens}[$self->{tokens_index}++])->[1] eq ':' and (($tokens[8] = $self->context_condition_block({})) and do { $context_value->{condition} = $tokens[8]; 1 }) and ($tokens[9] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '}') 
				or ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and $self->confess_at_current_offset('rule block expected'));
	$save_tokens_index = $self->{tokens_index};
	return $context_value;
}
sub context_strings_block {
	my ($self, $context_value) = @_;
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected !string_definition', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and (do { my $save_tokens_index = $self->{tokens_index}; while (((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and (($tokens[0] = $self->context_string_definition) and do { push @$context_value, $tokens[0]; 1 })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }));
	return $context_value;
}
sub context_string_definition {
	my ($self, $context_value) = @_;
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected [ \'$\', identifier token, \'=\', \'{\', /[0-9a-fA-F?]{2}/, \'}\', /xor|wide|ascii|nocase|base64|base64wide|fullword|private/ ]', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and (do { my $save_tokens_index = $self->{tokens_index}; if (((($self->{tokens_index} = $save_tokens_index) + 5 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '$' and (($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[0] eq 'identifier' and do { $context_value->{identifier} = $tokens[1][1]; 1 }) and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '=' and ($tokens[3] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '{' and (do { my $save_tokens_index = $self->{tokens_index}; while (((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and (($tokens[4] = $self->{tokens}[$self->{tokens_index}++])->[1] =~ /\A([0-9a-fA-F?]{2})\Z/ and do { push @{$context_value->{hex_values}}, $tokens[4][1]; 1 })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }) and ($tokens[5] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '}' and (do { my $save_tokens_index = $self->{tokens_index}; while (((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and (($tokens[6] = $self->{tokens}[$self->{tokens_index}++])->[1] =~ /\A(xor|wide|ascii|nocase|base64|base64wide|fullword|private)\Z/ and do { push @{$context_value->{modifiers}}, $tokens[6][1]; 1 })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }));
	return $context_value;
}
sub context_condition_block {
	my ($self, $context_value) = @_;
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected \'$\', identifier token', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 2 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '$' and ((($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[0] eq 'identifier' and do { $context_value->{identifier} = $tokens[1][1]; 1 }) and $context_value->{type} = 'variable_expression'));
	$save_tokens_index = $self->{tokens_index};
	return $context_value;
}
sub context_meta_block {
	my ($self, $context_value) = @_;
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected identifier token, \'=\', string token', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and (do { my $save_tokens_index = $self->{tokens_index}; while (((($self->{tokens_index} = $save_tokens_index) + 3 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[0] eq 'identifier' and ($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '=' and (($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[0] eq 'string' and do { $context_value->{$tokens[0][1]} = $tokens[2][1]; 1 })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }));
	return $context_value;
}


##############################
##### native perl functions
##############################

sub interpret_rule {
	my ($self, $def) = @_;

	my $cond = $def->{condition};
	if ($cond->{type} eq 'variable_expression') {
		my ($var) = grep $_->{identifier} eq $cond->{identifier}, @{ $def->{strings} };
		# say Data::Dumper::Dumper ($var);
		return $var->{value} =~ s/\A"(.*?)"\Z/$1/rs if exists $var->{value};
		return join '', map { pack 'H2', $_ } @{ $var->{hex_values} };
	} else {
		...
	}
}

sub main {
	require Data::Dumper;
	require Sugar::IO::File;

	my $parser = __PACKAGE__->new;
	foreach my $file (@_) {
		$parser->{filepath} = Sugar::IO::File->new($file);
		my $tree = $parser->parse;
		say Data::Dumper::Dumper ($tree);

		say $parser->interpret_rule($tree->[0]);
	}
}

caller or main(@ARGV);



1;


