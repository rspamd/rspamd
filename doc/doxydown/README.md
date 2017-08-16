# Doxydown - documentation utility

## Introduction

Doxydown is an utility to convert `doxygen`-like comments from the source code to markdown.
Unlike other documentation systems, `doxydown` is specifically designed to generate markdown output only.
At the moment, doxydown can work with C and lua comments and produce kramdown/pandoc or github
flavoured markdown. Doxydown produces output with anchors, links and table of content.
It also can highlight syntax for examples in the documentation.

### Why markdown

Markdown is used by many contemporary engines and can be rendered to HTML using
advanced templates, styles and scripts. Markdown provides excellent formatting
capabilities while it doesn't require authors to be web designers to create
documentation. Markdown is rendered by [`github`](https://github.com) and
doxydown can generate documentation easily viewed directly inside github. Moreover,
doxydown supports pandoc style of markdown and that means that markdown output 
can be converted to all formats supported by pandoc (html, pdf, latex,
man pages and many others).

### Why not `other documentation generator`

Doxydown is extremely simple as it can output markdown only but it is very
convenient tool to generate nice markdown with all features required from the
documentation system. Doxydown uses input format that is very close to `doxygen`
that allows to re-use the existing documentation comments. Currently, doxydown
does not support many features but they could be easily added on demand.

## Input format

Doxydown extracts documentation from the comments blocks. The start of block is indicated by

	/***  

in `C` or by

	--[[[

in `lua`. The end of documentation block is the normal multiline comment ending
specific for the input language. Doxydown also strips an initial comment character,
therefore the following inputs are equal:

~~~c
/***
 * some text
 * other text
 *
 */
~~~
and

~~~c
/***
some text
other text

*/
~~~

Note that doxydown preserves empty lines and all markdown elements.

### Documentation blocks

Each documentation block describes either module or function/method. Modules are
logical compounds of functions and methods. The difference between method and
function is significant for languages with methods support (e.g. by `lua` via
metatables). To define method or function you can use the following:

	/***
	@function my_awesome_function(param1[, param2])
	This function is awesome.
	*/ 

All text met in the current documentation block is used as function or method description.
You can also define parameters and return values for functions and methods:

	@param {type} param1 mandatory param

Here, `{type}` is optional type description for a parameter, `param1` is parameter's name
and the rest of the string is parameter description. Currently, you cannot split
parameter description by newline character. In future versions of doxydown this might
be fixed.

You can specify return type of your function by using of `@return` tag:

	@return {type} some cool result
	
This tag is similar to `@param` and has the same limitation regarding newlines.
You can also add some example code by using of `@example` tag:

	@example
	my_awesome_function('hello'); // returns 42

All text after `@example` tag and until documentation block end is used as an example
and is highlighted in markdown. Also you can switch the language of example by using
the extended `@example` tag:

	@example lua

In this example, the code will be highlighted as `lua` code.

Modules descriptions uses the same conventions, but `@param` and `@return` are
meaningless for the modules. Function and methods blocks that follows some `@module`
block are automatically attached to that module.

Both modules and function can use links to other functions and methods by using of
`@see` tag:

	@see my_awesome_function

This inserts a hyperlink to the specified function definition to the markdown.

## Output format

Doxydown can generate github flavoured markdown and pandoc/kramdown compatible
markdown. The main difference is in how anchors are organized. In kramdown and
pandoc it is possible to specify an explicit id for each header, whilst in
GH flavoured markdown we can use only implicit anchors.

### Examples

You can see an example of github flavoured markdown render at 
[libucl github page](https://github.com/vstakhov/libucl/blob/master/doc/lua_api.md).
The same page bu rendered by kramdown engine in `jekyll` platform can be 
accessed by [this address](https://rspamd.com/doc/lua/ucl.html).

## Program invocation

	doxydown [-hg] [-l language] < input_source > markdown.md

* `-h`: help message
* `-e`: sets default example language (default: lua)
* `-l`: sets input language (default: c)
* `-g`: use github flavoured markdown (default: kramdown/pandoc)

## License

Doxydown is published by terms of `MIT` license.