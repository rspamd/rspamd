---
layout: doc_modules
title: Regexp module
---
# Rspamd regexp module

This is a core module that deals with regexp expressions to filter messages.

## Principles of work

Regexp module operates with `expressions` - a logical sequence of different `atoms`. Atoms
are elements of the expression and could be represented as regular expressions, rspamd
functions and lua functions. Rspamd supports the following operators in expressions:

* `&&` - logical AND (can be also written as `and` or even `&`)
* `||` - logical OR (`or` `|`)
* `!` - logical NOT (`not`)
* `+` - logical PLUS, usually used with comparisons:
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

* Headers (should be `Header-Name=/regexp/flags`), mime headers
* Full headers string
* Textual mime parts
* Raw messages
* URLs

The match type is defined by special flags after the last `/` symbol:

* `H` - header regexp
* `X` - undecoded header regexp (e.g. without quoted-printable decoding)
* `B` - MIME header regexp (applied for headers in MIME parts only)
* `R` - full headers content (applied for all headers undecoded and for the message only - **not** including MIME headers)
* `M` - raw message regexp
* `P` - part regexp without HTML tags b64/qp decoded
* `Q` - raw part regexp with HTML tags unencoded
* `C` - spamassassin `BODY` regexp analogue(see http://spamassassin.apache.org/full/3.4.x/doc/Mail_SpamAssassin_Conf.txt)
* `D` - spamassassin `RAWBODY` regexp analogue (raw part regexp with HTML tags b64/qp decoded)
* `U` - URL regexp

From 1.3, it is also possible to specify long regexp types for convenience in curly braces:

* `{header}` - header regexp
* `{raw_header}` - undecoded header regexp (e.g. without quoted-printable decoding)
* `{mime_header}` - MIME header regexp (applied for headers in MIME parts only)
* `{all_header}` - full headers content (applied for all headers undecoded and for the message only - **not** including MIME headers)
* `{body}` - raw message regexp
* `{mime}` - part regexp without HTML tags
* `{raw_mime}` - part regexp with HTML tags
* `{sa_body}` - spamassassin `BODY` regexp analogue(see http://spamassassin.apache.org/full/3.4.x/doc/Mail_SpamAssassin_Conf.txt)
* `{sa_raw_body}` - spamassassin `RAWBODY` regexp analogue
* `{url}` - URL regexp

Each regexp also supports the following flags:

* `i` - ignore case
* `u` - use utf8 regexp
* `m` - multiline regexp - treat string as multiple lines. That is, change "^" and "$" from matching the start of the string's first line and the end of its last line to matching the start and end of each line within the string
* `x` - extended regexp - this flag tells the regular expression parser to ignore most whitespace that is neither backslashed nor within a bracketed character class. You can use this to break up your regular expression into (slightly) more readable parts. Also, the # character is treated as a metacharacter introducing a comment that runs up to the pattern's closing delimiter, or to the end of the current line if the pattern extends onto the next line.
* `s` - dotall regexp - treat string as single line. That is, change `.` to match any character whatsoever, even a newline, which normally it would not match. Used together, as `/ms`, they let the `.` match any character whatsoever, while still allowing `^` and `$` to match, respectively, just after and just before newlines within the string.
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

Lua atoms now can be lua global functions names or callbacks. This is 
a compatibility feature for previously written rules.

### Regexp objects

From rspamd 1.0, it is possible to add more power to regexp rules by using of
table notation while writing rules. A table can have the following fields:

- `callback`: lua callback for the rule
- `re`: regular expression (mutually exclusive with `callback` option)
- `condition`: function of task that determines when a rule should be executed
- `score`: default score
- `description`: default description
- `one_shot`: default one shot settings

Here is an example of table form definition of regexp rule:

~~~lua
config['regexp']['RE_TEST'] = {
    re = '/test/i{mime}',
    score = 10.0,
    condition = function(task)
        if task:get_header('Subject') then
            return true
        end
        return false
    end,
}
~~~
