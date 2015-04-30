# Trie plugin

Trie plugin is designed to search multiple strings within raw messages or text parts
doing this blazingly fast. In fact, it uses aho-corasic algorithm that performs incredibly
good even on large texts and many input strings.

This module provides a convenient interface to the search trie structure.

## Configuration

Here is an example of trie configuration:

~~~nginx
trie {
	# Each subsection defines a single rule with associated symbol
	SYMBOL1 {
		# Define rules in the file (it is *NOT* a map)
		file = "/some/path";
		# Raw rules search within the whole undecoded messages
		raw = true;
		# If we have multiple occurrences of strings from this rule
		# then we insert a symbol multiple times
		multi = true;
	}
	SYMBOL2 {
		patterns = [
			"pattern1",
			"pattern2",
			"pattern3"
		]
	}
}
~~~

Despite of the fact that aho-corasic trie is very fast, it supports merely plain
strings. Moreover, it cannot distinguish words boundaries, for example, a string
`test` will be found in texts `test`, `tests` or even `123testing`. Therefore, it
might be used to search some concrete and relatively specific patterns and should
not be used for words match.