# Lupa

## Introduction

Lupa is a [Jinja2][] template engine implementation written in Lua and supports
Lua syntax within tags and variables.

Lupa was sponsored by the [Library of the University of Antwerp][].

[Jinja2]: http://jinja.pocoo.org
[Library of the University of Antwerp]: http://www.uantwerpen.be/

## Requirements

Lupa has the following requirements:

* [Lua][] 5.1, 5.2, or 5.3.
* The [LPeg][] library.

[Lua]: http://www.lua.org
[LPeg]: http://www.inf.puc-rio.br/~roberto/lpeg/

## Download

Download Lupa from the project’s [download page][].

[download page]: download

## Installation

Unzip Lupa and place the "lupa.lua" file in your Lua installation's
`package.path`. This location depends on your version of Lua. Typical locations
are listed below.

* Lua 5.1: */usr/local/share/lua/5.1/* or */usr/local/share/lua/5.1/*
* Lua 5.2: */usr/local/share/lua/5.2/* or */usr/local/share/lua/5.2/*
* Lua 5.3: */usr/local/share/lua/5.3/* or */usr/local/share/lua/5.3/*

You can also place the "lupa.lua" file wherever you'd like and add it to Lua's
`package.path` manually in your program. For example, if Lupa was placed in a
*/home/user/lua/* directory, it can be used as follows:

    package.path = package.path..';/home/user/lua/?.lua'

## Usage

Lupa is simply a Lua library. Its `lupa.expand()` and `lupa.expand_file()`
functions may called to process templates. For example:

    lupa = require('lupa')
    lupa.expand("hello {{ s }}!", {s = "world"}) --> "hello world!"
    lupa.expand("{% for i in {1, 2, 3} %}{{ i }}{% endfor %}") --> 123

By default, Lupa loads templates relative to the current working directory. This
can be changed by reconfiguring Lupa:

    lupa.expand_file('name') --> expands template "./name"
    lupa.configure{loader = lupa.loaders.filesystem('path/to/templates')}
    lupa.expand_file('name') --> expands template "path/to/templates/name"

See Lupa's [API documentation][] for more information.

[API documentation]: api.html

## Syntax

Please refer to Jinja2's extensive [template documentation][]. Any
incompatibilities are listed in the sections below.

[template documentation]: http://jinja.pocoo.org/docs/dev/templates/

## Comparison with Jinja2

While Lua and Python (Jinja2's implementation language) share some similarities,
the languages themselves are fundamentally different. Nevertheless, a
significant effort was made to support a vast majority of Jinja2's Python-style
syntax. As a result, Lupa passes Jinja2's test suite with only a handful of
modifications. The comprehensive list of differences between Lupa and Jinja2 is
described in the following sections.

### Fundamental Differences

* Expressions use Lua's syntax instead of Python's, so many of Python's
  syntactic constructs are not valid. However, the following constructs
  *are valid*, despite being invalid in pure Lua:

  + Iterating over table literals or table variables directly in a "for" loop:

        {% for i in {1, 2, 3} %}...{% endfor %}

  + Conditional loops via an "if" expression suffix:

        {% for x in range(10) if is_odd(x) %}...{% endfor %}

  + Table unpacking for list elements when iterating through a list of lists:

        {% for a, b, c in {{1, 2, 3}, {4, 5, 6}} %}...{% endfor %}

  + Default values for macro arguments:

        {% macro m(a, b, c='c', d='d') %}...{% endmacro %}

* Strings do not have unicode escapes nor is unicode interpreted in any way.

### Syntactic Differences

* Line statements are not supported due to parsing complexity.
* In `{% for ... %}` loops, the `loop.length`, `loop.revindex`,
  `loop.revindex0`, and `loop.last` variables only apply to sequences, where
  Lua's `'#'` operator applies.
* The `{% continue %}` and `{% break %}` loop controls are not supported due to
  complexity.
* Loops may be used recursively by default, so the `recursive` loop modifier is
  not supported.
* The `is` operator is not supported by Lua, so tests of the form `{{ x is y }}`
  should be written `{{ is_y(x) }}` (e.g. `{{ is_number(42) }}`).
* Filters cannot occur after tokens within an expression (e.g.
  `{{ "foo"|upper .. "bar"|upper }}`), but can only occur at the end of an
  expression (e.g. `{{ "foo".."bar"|upper }}`).
* Blocks always have access to scoped variables, so the `scoped` block modifier
  is not supported.
* Named block end tags are not supported since the parser cannot easily keep
  track of that state information.
* Any `{% block ... %}` tags within a "false" block (e.g. `{% if a %}` where `a`
  evaluates to `false`) are never read and stored due to the parser
  implementation.
* Inline "if" expressions (e.g. `{% extends b if a else c %}`) are not
  supported. Instead, use a Lua conditional expression
  (e.g. `{% extends a and b or c %}`).
* Any `{% extends ... %}` tags within a sub-scope are not effective outside that
  scope (e.g. `{% if a %}{% extends a %}{% else %}{% extends b %}{% endif %}`).
  Instead, use a Lua conditional expression (e.g. `{% extends a or b %}`).
* Macros are simply Lua functions and have no metadata attributes.
* Macros do not have access to a `kwargs` variable since Lua does not support
  keyword arguments.
* `{% from x import y %}` tags are not supported. Instead, you must use either
  `{% import x %}`, which imports all globals in `x` into the current
  environment, or use `{% import x as z %}`, which imports all globals in `x`
  into the variable `z`.
* `{% set ... %}` does not support multiple assignment. Use `{% do ...%}`
  instead. The catch is that `{% do ... %}` does not support filters.
* The `{% trans %}` and `{% endtrans %}` tags, `{% with %}` and `{% endwith %}`
  tags, and `{% autoescape %}` and `{% endautoescape %}` tags are not supported
  since they are outside the scope of this implementation.

### Filter Differences

* Only the `batch`, `groupby`, and `slice` filters return generators which
  produce one item at a time when looping. All other filters that produce
  iterable results generate all items at once.
* The `float` filter only works in Lua 5.3 since that version of Lua has a
  distinction between floats and integers.
* The `safe` filter must appear at the end of a filter chain since its output
  cannot be passed to any other filter.

### Function Differences

* The global `range(n)` function returns a sequence from 1 to `n`, inclusive,
  since lists start at 1 in Lua.
* No `lipsum()`, `dict()`, or `joiner()` functions for the sake of simplicity.

### API Differences

* Lupa has a much simpler API consisting of just four functions and three
  fields:

  + `lupa.expand()`: Expands a string template subject to an environment.
  + `lupa.expand_file()`: Expands a file template subject to an environment.
  + `lupa.configure()` Configures delimiters and template options.
  + `lupa.reset()`: Resets delimiters and options to their defaults.
  + `lupa.env`: The default environment for templates.
  + `lupa.filters`: The set of available filters (`escape`, `join`, etc.).
  + `lupa.tests`: The set of available tests (`is_odd`, `is_defined`, etc.).

* There is no bytecode caching.
* Lupa has no extension mechanism. Instead, modify `lupa.env`, `lupa.filters`,
  and `lupa.tests` directly. However, the parser cannot be extended.
* Sandboxing is not supported, although `lupa.env` is safe by default (`io`,
  `os.execute`, `os.remove`, etc. are not available).
