
all: build test

build:
	~/src/perl/repo/Sugar/Lang/SugarGrammarCompiler.pm grammer/YaraParse.sugar > YaraParse.pm
	chmod +x YaraParse.pm

test:
# 	./YaraParse.pm examples/xor_example.yara
	./YaraParse.pm examples/hex_example.yara


