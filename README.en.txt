API.
===========

API of rspamd is described in Doxygen documentation.

Logic of operation of rspamd filters.
==============================

1) All filters are registered in a config a file in the description of chains of filters:
header_filters = "regexp, my_func"
Where the filter name is or the name c the unit, or the name of script (lua or perl) function 
Types of filters:
* header_filters - the filters of headers
* mime_filters - the filters for every mime part
* message_filters - the filters of message without mime parsing
* url_filters - filters of URLs in messages

Filter register their results in metrics.

2) The Metric is a character value in which filters register their results.
There is a metrics by default - "default".
For each metrics there is a special function of consolidation which calculates coefficients
of results according to the internal logic of correspondence of characters and coefficients. 
By default the such function is the simple sum that can be configured in a configuration file:

# the Block factors
factors {
	# For example, "SURBL_DNS" =5.0
	"SYMBOL_NAME" = coefficient;
};

Also for the metrics it is possible to register special consolidation function:

metric {
	name = "test_metric";
	function = "some_function";
	required_score = 20.0;
};


The protocol.
=========

Answer format:
SPAMD/1.1 0 EX_OK 
      \/  \/   \/
  Version Code Errors
Spam: False; 2 / 5
It is a format of compatibility with sa-spamd (without metrics)

New format of the answer:
RSPAMD/1.0 0 EX_OK
Metric: Name; Spam_Result; Spam_Mark / Spam_Mark_Required
Metric: Name2; Spam_Result2; Spam_Mark2 / Spam_Mark_Required2

Type headers metric can be a little.
Format of output of characters:
SYMBOL1, SYMBOL2, SYMBOL3 - a format of compatibility with sa-spamd
Symbol: Name; Param1, Param2, Param3 - a format rspamd

The answer format:
PROCESS SPAMC/1.2
\/      \/
Command Version

SPAMC - the protocol of compatibility with sa-spamd
RSPAMC - new rspamd protocol
In any of operating modes following headers are supported:
Content-Length - Length of the message
Helo - HELO, received from the client
From - MAIL FROM
IP - IP of the client
Recipient-Number - Number of recipients
Rcpt - the recipient
Queue-ID - The queue identifier

These values can be used in filters rspamd.

Regular expressions
====================

Regular expressions are described in regexp module
.module ' regexp ' {
	SYMBOL = "regexp_expression";
};
header_filters = "regexp";

Format of regular expression:
"/pattern/flags"
Also for header lines there is special regexp line:
headername =/pattern/flags

Flags of regexp:
i, m, s, x, u, o - same, as at perl/pcre
r - raw not coded in utf8 regexp
H - searches for a header
M - searches in undecoded message
P - searches in decoded mime parts
U - searches in urls
X - searches in undecoded headers

Expression can contain regular expressions, functions, operators of logic and brackets:
SOME_SYMBOL = "To =/blah@blah/H AND! (From =/blah@blah/H | Subject =/blah/H)"

Also it is possible to use variables:
$to_blah = "To =/blah@blah/H";
$from_blah = "From =/blah@blah/H";
$subject_blah = "Subject =/blah/H";

Then the previous expression will be such:

SOME_SYMBOL = "$ {to_blah} AND! ($ {from_blah} | $ {subject_blah})"

Logic expressions rspamd
===========================

Expressions containing regular expressions, functions, logic operations, brackets, can be used
for the filtering. General rules:
- Logic operations can be boolean "And": ' & ', boolean "OR": ' | ' and boolean negation: '! '.
- A priority of logic operations: &| -> !, for priority change it is possible to use brackets:
 (A AND! B) |! (C|D)
- Space symbols in expressions are ignored
- The operand containing/re/args or string =/re/args is considered regular expression, in regular
expressions all symbols ' / ' and ' "' should be escaped by a symbol ' \', but symbol '\' is not need to be escaped.
- The operand which accepts arguments, is considered function. Arguments of function can be expressions, regexps or other functions.
Arguments in function are evaluated from left to right.
- There is a number of built-in functions:
  * header_exists - accepts header's name as argument, returns true if such heading exists
  * compare_parts_distance - accepts as argument number from 0 to 100 which reflects a difference in percentage
    between letter parts. Function works with the messages containing 2 text parts (text/plain and text/html) and
	returns true when these parts differ more than on N percent. If the argument is not specified,
	function searches for completely different parts.
  * compare_transfer_encoding - compares Content-Transfer-Encoding with the argument
  * content_type_compare_param - compares Content-Type param with regular expression or line:
     content_type_compare_param (Charset,/windows-\d +/)
	 content_type_compare_param (Charset, ascii)
  * content_type_has_param - checks for specified Content-Type parameter
  * content_type_is_subtype - compares a subtype of content-type to regular expression or line
  * content_type_is_type - compares type of content-type to regular expression or line
     content_type_is_type (text)
     content_type_is_subtype (/?.html/)
  * regexp_match_number - accepts as the number of matched expressions as first parameter number and list of expressions. 
    If the number of matched expressions is more than first argument function returns TRUE, for example:
	regexp_match_number (2, $ {__ RE1}, $ {__ RE2}, header_exists (Subject))
  * has_only_html_part - function returns TRUE if there is only HTML part in the message
  * compare_recipients_distance - calculates percent of similar recipients of the message. Accepts argument - a threshold in 
    percentage of similar recipients.
  * is_recipients_sorted - returns TRUE if the list of addressees is sorted (works only if the number of addressees> = 5).
  * is_html_balanced - returns TRUE if tags in all html parts are balanced
  * has_html_tag - returns TRUE if specified html tag is found

The module chartable.
================

The module is intended for search of words with the mixed symbols, for example:
kашa - a part in a Latin, and a part in Cyrillics.
Module parametres:

.module ' chartable ' {
	metric = "default";
	symbold = "R_MIXED_CHARSET";
	threshold = "0.1";
};

threshold is a relation of transitions between codings to total number of symbols in words, for example, we have a word
"kаша" (the first letter Latin), then total number of transitions - 3, and number of transitions between codings - 1, then 
The relation - 1/3.

For inclusion of the module he is necessary for adding in the list mime_filters:
mime_filters = "chartable";
