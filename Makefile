
all: build test run

build:
	~/src/perl/repo/Sugar/Lang/SugarGrammarCompiler.pm --standalone grammar/YaraParse.sugar > YaraParse.pm
	chmod +x YaraParse.pm

run:
	./YaraParse.pm malware_yaras/* > malware_block
	cat dllhost_64.exe malware_block > dllhost_64_exciting.exe

test:
	./YaraParse.pm examples/xor_example.yara
	./YaraParse.pm examples/hex_example.yara
	./YaraParse.pm examples/regex_example.yara




