# Rspamd regexp module

This is a core module that deals with regexp expressions to filter messages.

## Principles of work

Regexp module operates with `expressions` - a logical sequence of different `atoms`. Atoms
are elements of the expression and could be represented as regular expressions, rspamd
functions and lua functions. Rspamd supports the following operators in expressions:

* `&&` - logical AND (can be also written as `and` or even `&`)
* `||` - logical OR (`or` `|`)
* `!` - logical NOT (`not`)
* `+` - logical PLUS, usually used with comparisions:
	- `>` more than
	- `<` less than
	- `>=` more or equal
	- `<=` less or equal

Whilst logical operators are clear for understanding, PLUS is not so clear. In rspamd,
it is used to join multiple atoms or subexpressions and compare them to a specific number:

	A + B + C + D > 2 - evaluates to `true` if at least 3 operands are true
	(A & B) + C + D + E >= 2 -  evaluates to `true` if at least 2 operands are true

Operators has their own priorities:
	
1. NOT
2. PLUS
3. COMPARE
4. AND
5. OR

You can change priorities by braces, of course. All operations are *right* associative in rspamd.
While evaluating expressions, rspamd tries to optimize their execution time by reordering and does not evaluate
unnecessary branches.

## Expressions components

Rspamd support the following components within expressions:

* Regular expressions
* Internal functions
* Lua global functions (not widely used)

### Regular expressions

In rspamd, regular expressions could match different parts of messages:

* Headers (should be `Header-Name=/regexp/flags`)
* Textual mime parts
* Raw messages
* URLs

The match type is defined by special flags after the last `/` symbol:

* `H` - header regexp
* `M` - raw message regexp
* `P` - part regexp
* `U` - URL regexp

We strongly discourage from using of raw message regexps as they are expensive and
should be replaced by [trie](trie.md) rules if possible.

Each regexp also supports the following flags:

* `i` - ignore case
* `u` - use utf8 regexp
* `m` - multiline regexp
* `x` - extended regexp
* `O` - do not optimize regexp (rspamd optimizes regexps by default)

### Internal functions

Rspamd supports a set of internal functions to do some common spam filtering tasks:

* `check_smtp_data(type[, str or /re/])` - checks for the specific envelope argument: `from`, `rcpt`, `user`, `subject`
* `compare_encoding(str or /re/)` - compares message encoding with string or regexp
* `compare_parts_distance(inequality_percent)` - if a message is multipart/alternative, compare two parts and return `true` if they are inequal more than `inequality_percent`
* `compare_recipients_distance(inequality_percent)` - check how different are recipients of a message (works for > 5 recipients)
* `compare_transfer_encoding(str or /re/)` - compares message transfer encoding with string or regexp
* `content_type_compare_param(param, str or /re/)` - compare content-type parameter `param` with string or regexp
* `content_type_has_param(param)` - return true if `param` exists in content-type
* `content_type_is_subtype(str or /re/` - return `true` if subtype of content-type matches string or regexp
* `content_type_is_type(str or /re/)`- return `true` if type of content-type matches string or regexp
* `has_content_part(type)` - return `true` if the part with the specified `type` exists
* `has_content_part_len(type, len)` - return `true` if the part with the specified `type` exists and have at least `len` lenght
* `has_fake_html()` - check if there is an HTML part in message with no HTML tags
* `has_html_tag(tagname)` - return `true` if html part contains specified tag
* `has_only_html_part()` - return `true` if there is merely a single HTML part
* `header_exists(header)` - return if a specified header exists in the message
* `is_html_balanced()` - check whether HTML part has balanced tags
* `is_recipients_sorted()` - return `true` if there are more than 5 recipients in a message and they are sorted
* `raw_header_exists()` - does the same as `header_exists`

Many of these functions are just legacy but they are supported in terms of compatibility.

### Lua atoms

Lua atoms now can be lua global functions names. This is supported merely for compatibility and it is 
a subject of future redesign.