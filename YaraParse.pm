#!/usr/bin/env perl
package YaraParse;
use strict;
use warnings;

use feature 'say';





##############################
##### variables and settings
##############################



our $tokens = [
	'whitespace' => qr/\s++/s,
	'comment' => qr/\/\*.*?\*\/|\/\/[^\n]*\n/s,
	'regex' => qr/\/(?:[^\\\/]|\\.)*+\/[is]*+/s,
	'string' => qr/"(?:[^"\\]|\\["\\rtn]|\\x[0-9a-fA-F]{2})*"/s,
	'identifier' => qr/[a-zA-Z_][a-zA-Z0-9_]*+/,
	'symbol' => qr/==|\$|\{|\}|\[|\]|,|:|=|\*|\(|\)/,
	'hex_byte' => qr/[0-9a-fA-F?]{2}(?![0-9a-fA-F?])/,
	'hex_number' => qr/0x[0-9a-fA-F]+/,
	'number' => qr/-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][\+\-]?[0-9]+)?/,
];

our $ignored_tokens = [
	'whitespace',
	'comment',
];

our $contexts = {
	root => 'context_root',
	rule_set => 'context_rule_set',
	rule_block => 'context_rule_block',
	strings_block => 'context_strings_block',
	string_definition => 'context_string_definition',
	string_value_definition => 'context_string_value_definition',
	condition_block => 'context_condition_block',
	condition_expression => 'context_condition_expression',
	more_condition_expression => 'context_more_condition_expression',
	variable_list => 'context_variable_list',
	meta_block => 'context_meta_block',
};



##############################
##### api
##############################



sub new {
	my ($class, %opts) = @_;
	my $self = bless {}, $class;

	$self->{filepath} = Sugar::IO::File->new($opts{filepath}) if defined $opts{filepath};
	$self->{text} = $opts{text} if defined $opts{text};

	$self->{token_regexes} = $tokens // die "token_regexes argument required for Sugar::Lang::Tokenizer";
	$self->{ignored_tokens} = $ignored_tokens;

	$self->compile_tokenizer_regex;

	return $self
}

sub parse {
	my ($self) = @_;
	return $self->parse_from_context("context_root");
}

sub parse_from_context {
	my ($self, $context) = @_;
	$self->parse_tokens;

	$self->{syntax_tree} = $self->$context($self->{syntax_tree});
	$self->confess_at_current_offset("more tokens after parsing complete") if $self->{tokens_index} < @{$self->{tokens}};

	return $self->{syntax_tree};
}

sub compile_tokenizer_regex {
	my ($self) = @_;
	use re 'eval';
	my $token_pieces = join '|',
			map "($self->{token_regexes}[$_*2+1])(?{'$self->{token_regexes}[$_*2]'})",
				0 .. $#{$self->{token_regexes}} / 2;
	$self->{tokenizer_regex} = qr/$token_pieces/s;

# 	# optimized selector for token names, because %+ is slow
# 	my @index_names = map $self->{token_regexes}[$_*2], 0 .. $#{$self->{token_regexes}} / 2;
# 	my @index_variables = map "\$$_", 1 .. @index_names;
# 	my $index_selectors = join "\n\tels",
# 			map "if (defined $index_variables[$_]) { return '$index_names[$_]', $index_variables[$_]; }",
# 			0 .. $#index_names;

# 	$self->{token_selector_callback} = eval "
# sub {
# 	$index_selectors
# }
# ";
}

sub parse_tokens {
	my ($self) = @_;

	my $text;
	$text = $self->{filepath}->read if defined $self->{filepath};
	$text = $self->{text} unless defined $text;

	die "no text or filepath specified before parsing" unless defined $text;

	return $self->parse_tokens_in_text($text)
}


sub parse_tokens_in_text {
	my ($self, $text) = @_;
	$self->{text} = $text;
	
	my @tokens;

	my $line_number = 1;
	my $offset = 0;

	# study $text;
	while ($text =~ /\G$self->{tokenizer_regex}/gco) {
		# despite the absurdity of this solution, this is still faster than loading %+
		# my ($token_type, $token_text) = each %+;
		# my ($token_type, $token_text) = $self->{token_selector_callback}->();
		my ($token_type, $token_text) = ($^R, $^N);

		push @tokens, [ $token_type => $token_text, $line_number, $offset ];
		$offset = pos $text;
		# amazingly, this is faster than a regex or an index count
		# must be because perl optimizes out the string modification, and just performs a count
		$line_number += $token_text =~ y/\n//;
	}

	die "parsing error on line $line_number:\nHERE ---->" . substr ($text, pos $text // 0, 200) . "\n\n\n"
			if not defined pos $text or pos $text != length $text;

	if (defined $self->{ignored_tokens}) {
		foreach my $ignored_token (@{$self->{ignored_tokens}}) {
			@tokens = grep $_->[0] ne $ignored_token, @tokens;
		}
	}

	# @tokens = $self->filter_tokens(@tokens);

	$self->{tokens} = \@tokens;
	$self->{tokens_index} = 0;
	$self->{save_tokens_index} = 0;

	return $self->{tokens}
}

sub confess_at_current_offset {
	my ($self, $msg) = @_;

	my $position;
	my $next_token = '';
	if ($self->{tokens_index} < @{$self->{tokens}}) {
		$position = 'line ' . $self->{tokens}[$self->{tokens_index}][2];
		my ($type, $val) = @{$self->{tokens}[$self->{tokens_index}]};
		$next_token = " (next token is $type => <$val>)";
	} else {
		$position = 'end of file';
	}

	# say $self->dump_at_current_offset;

	die "error on $position: $msg$next_token";
}
sub confess_at_offset {
	my ($self, $msg, $offset) = @_;

	my $position;
	my $next_token = '';
	if ($offset < @{$self->{tokens}}) {
		$position = 'line ' . $self->{tokens}[$offset][2];
		my ($type, $val) = ($self->{tokens}[$offset][0], $self->{tokens}[$offset][1]);
		$next_token = " (next token is $type => <$val>)";
	} else {
		$position = 'end of file';
	}

	# say $self->dump_at_current_offset;

	die "error on $position: $msg$next_token";
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
	$self->confess_at_offset('expected [ \'private\' ], \'rule\', !rule_block', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and (do { my $save_tokens_index = $self->{tokens_index}; while (((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and (do { my $save_tokens_index = $self->{tokens_index}; if (((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'private'))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }) and ($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'rule' and (($tokens[2] = $self->context_rule_block) and do { push @$context_value, $tokens[2]; 1 })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }));
	return $context_value;
}
sub context_rule_block {
	my ($self, $context_value) = @_;
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected identifier token, [ \':\', identifier token ], \'{\', [ \'meta\', \':\', !meta_block ], \'strings\', \':\', !strings_block, \'condition\', \':\', !condition_block, \'}\' or ', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 7 <= @{$self->{tokens}}) and (($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[0] eq 'identifier' and do { $context_value->{identifier} = $tokens[0][1]; 1 }) and (do { my $save_tokens_index = $self->{tokens_index}; if (((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and ($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] eq ':' and (do { my $save_tokens_index = $self->{tokens_index}; while (((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and (($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[0] eq 'identifier' and do { push @{$context_value->{tags}}, $tokens[2][1]; 1 })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }) and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '{' and (do { my $save_tokens_index = $self->{tokens_index}; if (((($self->{tokens_index} = $save_tokens_index) + 2 <= @{$self->{tokens}}) and ($tokens[3] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'meta' and ($tokens[4] = $self->{tokens}[$self->{tokens_index}++])->[1] eq ':' and (($tokens[5] = $self->context_meta_block({})) and do { $context_value->{meta} = $tokens[5]; 1 })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }) and ($tokens[4] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'strings' and ($tokens[5] = $self->{tokens}[$self->{tokens_index}++])->[1] eq ':' and (($tokens[6] = $self->context_strings_block([])) and do { $context_value->{strings} = $tokens[6]; 1 }) and ($tokens[7] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'condition' and ($tokens[8] = $self->{tokens}[$self->{tokens_index}++])->[1] eq ':' and (($tokens[9] = $self->context_condition_block) and do { $context_value->{condition} = $tokens[9]; 1 }) and ($tokens[10] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '}') 
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
	$self->confess_at_offset('expected [ \'$\', /[a-zA-Z0-9_]*+/, \'=\', !string_value_definition, /xor|wide|ascii|nocase|base64|base64wide|fullword|private/ ]', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and (do { my $save_tokens_index = $self->{tokens_index}; if (((($self->{tokens_index} = $save_tokens_index) + 3 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '$' and (($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] =~ /\A([a-zA-Z0-9_]*+)\Z/ and do { $context_value->{identifier} = $tokens[1][1]; 1 }) and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '=' and (($tokens[3] = $self->context_string_value_definition($context_value)) and (($context_value = $tokens[3]) or do { 1 })) and (do { my $save_tokens_index = $self->{tokens_index}; while (((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and (($tokens[4] = $self->{tokens}[$self->{tokens_index}++])->[1] =~ /\A(xor|wide|ascii|nocase|base64|base64wide|fullword|private)\Z/ and do { push @{$context_value->{modifiers}}, $tokens[4][1]; 1 })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }));
	return $context_value;
}
sub context_string_value_definition {
	my ($self, $context_value) = @_;
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected \'{\', /[0-9a-fA-F?]{2}/, \'}\' or string token or regex token or ', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 2 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '{' and (do { my $save_tokens_index = $self->{tokens_index}; while (((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and (($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] =~ /\A([0-9a-fA-F?]{2})\Z/ and do { push @{$context_value->{hex_values}}, $tokens[1][1]; 1 })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }) and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '}') 
				or ((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and (($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[0] eq 'string' and do { $context_value->{value} = $tokens[0][1]; 1 })) 
				or ((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and (($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[0] eq 'regex' and do { $context_value->{regex_value} = $tokens[0][1]; 1 })) 
				or ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and $self->confess_at_current_offset('string value expected'));
	$save_tokens_index = $self->{tokens_index};
	return $context_value;
}
sub context_condition_block {
	my ($self, $context_value) = @_;
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected !more_condition_expression', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and (($tokens[0] = $self->context_more_condition_expression($self->context_condition_expression)) and (($context_value = $tokens[0]) or do { 1 })));
	$save_tokens_index = $self->{tokens_index};
	return $context_value;
}
sub context_condition_expression {
	my ($self, $context_value) = @_;
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected \'$\', identifier token or \'any\', \'of\', \'them\',  or \'any\', \'of\', \'(\', !variable_list, \')\' or \'all\', \'of\', \'them\',  or \'all\', \'of\', \'(\', !variable_list, \')\' or /\\d+/, \'of\', \'them\', ,  or /\\d+/, \'of\', \'(\', !variable_list, \')\',  or \'uint16\', \'(\', \'0\', \')\', \'==\', /0x5A4D/i,  or \'(\', !more_condition_expression, \')\' or identifier token or ', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 2 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '$' and ((($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[0] eq 'identifier' and do { $context_value->{identifier} = $tokens[1][1]; 1 }) and $context_value->{type} = 'variable_expression')) 
				or ((($self->{tokens_index} = $save_tokens_index) + 3 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'any' and ($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'of' and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'them' and ((1 and do { $context_value->{all} = '1'; 1 }) and $context_value->{type} = 'any_of_expression')) 
				or ((($self->{tokens_index} = $save_tokens_index) + 4 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'any' and ($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'of' and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '(' and ((($tokens[3] = $self->context_variable_list([])) and do { $context_value->{variables} = $tokens[3]; 1 }) and $context_value->{type} = 'any_of_expression') and ($tokens[4] = $self->{tokens}[$self->{tokens_index}++])->[1] eq ')') 
				or ((($self->{tokens_index} = $save_tokens_index) + 3 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'all' and ($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'of' and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'them' and ((1 and do { $context_value->{all} = '1'; 1 }) and $context_value->{type} = 'all_of_expression')) 
				or ((($self->{tokens_index} = $save_tokens_index) + 4 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'all' and ($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'of' and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '(' and ((($tokens[3] = $self->context_variable_list([])) and do { $context_value->{variables} = $tokens[3]; 1 }) and $context_value->{type} = 'all_of_expression') and ($tokens[4] = $self->{tokens}[$self->{tokens_index}++])->[1] eq ')') 
				or ((($self->{tokens_index} = $save_tokens_index) + 3 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] =~ /\A(\d+)\Z/ and ($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'of' and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'them' and ((1 and do { $context_value->{all} = '1'; 1 }) and $context_value->{type} = 'number_of_expression') and (1 and do { $context_value->{number} = $tokens[0][1]; 1 })) 
				or ((($self->{tokens_index} = $save_tokens_index) + 4 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] =~ /\A(\d+)\Z/ and ($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'of' and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '(' and ((($tokens[3] = $self->context_variable_list([])) and do { $context_value->{variables} = $tokens[3]; 1 }) and $context_value->{type} = 'number_of_expression') and ($tokens[4] = $self->{tokens}[$self->{tokens_index}++])->[1] eq ')' and (1 and do { $context_value->{number} = $tokens[0][1]; 1 })) 
				or ((($self->{tokens_index} = $save_tokens_index) + 6 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'uint16' and ($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '(' and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '0' and ($tokens[3] = $self->{tokens}[$self->{tokens_index}++])->[1] eq ')' and ($tokens[4] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '==' and ($tokens[5] = $self->{tokens}[$self->{tokens_index}++])->[1] =~ /\A(0x5A4D)\Z/i and ((1 and do { $context_value->{all} = '1'; 1 }) and $context_value->{type} = 'free_expression')) 
				or ((($self->{tokens_index} = $save_tokens_index) + 2 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '(' and ((($tokens[1] = $self->context_more_condition_expression($self->context_condition_expression)) and do { $context_value->{expression} = $tokens[1]; 1 }) and $context_value->{type} = 'parenthesis_expression') and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq ')') 
				or ((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and ((($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[0] eq 'identifier' and do { $context_value->{identifier} = $tokens[0][1]; 1 }) and $context_value->{type} = 'rule_expression')) 
				or ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and $self->confess_at_current_offset('condition expected'));
	$save_tokens_index = $self->{tokens_index};
	return $context_value;
}
sub context_more_condition_expression {
	my ($self, $context_value) = @_;
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected \'or\',  or \'and\',  or ', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'or' and (1 and (($context_value = { type => 'or_expression', line_number => $tokens[0][2], left => $context_value, right => $self->context_more_condition_expression($self->context_condition_expression), }) or do { 1 }))) 
				or ((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq 'and' and (1 and (($context_value = { type => 'and_expression', line_number => $tokens[0][2], left => $context_value, right => $self->context_more_condition_expression($self->context_condition_expression), }) or do { 1 }))) 
				or ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and (return $context_value));
	$save_tokens_index = $self->{tokens_index};
	return $context_value;
}
sub context_variable_list {
	my ($self, $context_value) = @_;
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected \'$\', identifier token, [ \'*\' ], [ \',\' or  ]', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and (do { my $save_tokens_index = $self->{tokens_index}; while (((($self->{tokens_index} = $save_tokens_index) + 2 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '$' and (($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[0] eq 'identifier' and do { push @$context_value, $tokens[1][1]; 1 }) and (do { my $save_tokens_index = $self->{tokens_index}; if (((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and ($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '*'))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }) and (do { my $save_tokens_index = $self->{tokens_index}; if (((($self->{tokens_index} = $save_tokens_index) + 1 <= @{$self->{tokens}}) and ($tokens[3] = $self->{tokens}[$self->{tokens_index}++])->[1] eq ',') 
				or ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and (return $context_value)))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }));
	return $context_value;
}
sub context_meta_block {
	my ($self, $context_value) = @_;
	my @tokens;
	my $save_tokens_index = $self->{tokens_index};

	$save_tokens_index = $self->{tokens_index};
	$self->confess_at_offset('expected identifier token, \'=\', /"(?:[^"\\\\]|\\\\["\\\\rtn]|\\\\x[0-9a-fA-F]{2})*"|\\d+/s', $save_tokens_index)
		unless ((($self->{tokens_index} = $save_tokens_index) + 0 <= @{$self->{tokens}}) and (do { my $save_tokens_index = $self->{tokens_index}; while (((($self->{tokens_index} = $save_tokens_index) + 3 <= @{$self->{tokens}}) and ($tokens[0] = $self->{tokens}[$self->{tokens_index}++])->[0] eq 'identifier' and ($tokens[1] = $self->{tokens}[$self->{tokens_index}++])->[1] eq '=' and (($tokens[2] = $self->{tokens}[$self->{tokens_index}++])->[1] =~ /\A("(?:[^"\\]|\\["\\rtn]|\\x[0-9a-fA-F]{2})*"|\d+)\Z/s and do { $context_value->{$tokens[0][1]} = $tokens[2][1]; 1 })))
								{ $save_tokens_index = $self->{tokens_index}; }
								$self->{tokens_index} = $save_tokens_index; 1; }));
	return $context_value;
}


##############################
##### native perl functions
##############################

sub interpret_regex {
	my ($self, $regex) = @_;

	$regex =~ s#\A/(.*?)/\Z#$1#s;

	die 'regex unsupported';
}

sub interpret_rule_string {
	my ($self, $var) = @_;

	return $var->{value} =~ s/\A"(.*?)"\Z/$1/rs if exists $var->{value};
	return $self->interpret_regex($var->{regex_value}) if exists $var->{regex_value};
	return join '', map { pack 'H2', $_ } map { y/?/0/r } @{ $var->{hex_values} };
}

sub interpret_condition {
	my ($self, $def, $cond) = @_;

	if ($cond->{type} eq 'variable_expression') {
		my ($var) = grep $_->{identifier} eq $cond->{identifier}, @{ $def->{strings} };
		return $self->interpret_rule_string($var);
	} elsif ($cond->{type} eq 'any_of_expression' and $cond->{all}) {
		return $self->interpret_rule_string($def->{strings}[0]);
	} elsif ($cond->{type} eq 'all_of_expression' and $cond->{all}) {
		return join '', map $self->interpret_rule_string($_), @{ $def->{strings} };
	} elsif ($cond->{type} eq 'number_of_expression' and $cond->{all}) {
		return join '', map $self->interpret_rule_string($_), @{ $def->{strings} }[ 0 .. int($cond->{number} - 1) ];
	} elsif ($cond->{type} eq 'parenthesis_expression') {
		return $self->interpret_condition($def, $cond->{expression});
	} elsif ($cond->{type} eq 'or_expression') {
		return $self->interpret_condition($def, $cond->{left});
	} elsif ($cond->{type} eq 'and_expression') {
		return join '', $self->interpret_condition($def, $cond->{left}), $self->interpret_condition($def, $cond->{right});
	} elsif ($cond->{type} eq 'rule_expression') {
		die "trying to use failed rule: $cond->{identifier}" unless exists $self->{interpreted_rules_cache}{ $cond->{identifier} };
		return $self->{interpreted_rules_cache}{ $cond->{identifier} };
	} elsif ($cond->{type} eq 'free_expression') {
		return '';
	} else {
		die "rule condition unsupported: $cond->{type}";
	}
}

sub interpret_rule {
	my ($self, $def) = @_;

	my $cond = $def->{condition};
	my $res = $self->interpret_condition($def, $cond);

	$self->{interpreted_rules_cache}{ $def->{identifier} } = $res;

	return $res;
}

sub main {
	require Data::Dumper;
	require Sugar::IO::File;

	foreach my $file (@_) {
		eval {
			my $parser = __PACKAGE__->new;
			$parser->{filepath} = Sugar::IO::File->new($file);
			my $tree = $parser->parse;
			# say Data::Dumper::Dumper ($tree);

			say join '', map {
					# say Data::Dumper::Dumper ($_);
					my $ret = eval { $parser->interpret_rule($_) };
					warn "err: $@" if $@;
					if ($@) {
						'';
					} else {
						$ret;
					}
				} @{ $tree };
		};

		warn "failed to process $file: $@" if $@;
	}
}

caller or main(@ARGV);



1;


