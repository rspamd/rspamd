---
layout: doc_modules
title: Once received module
---
# Once received module

This module is intended to do simple checks for mail with one `Received` header. The idea behind these checks is that legitimate mail likely has more than one received and some bad patterns, such as `dynamic` or `broadband` are common for spam from hacked users' machines.

## Configuration

The configuration of this module is pretty straightforward: specify `symbol` for generic one received mail, specify `symbol_strict` for emails with bad patterns or with unresolvable hostnames and add **good** and **bad** patterns. Patterns can contain [lua patterns](http://lua-users.org/wiki/PatternsTutorial). `good_host` lines are used to negate this module for certain hosts, `bad_host` lines are used to specify certain bad patterns. It is also possible to specify `whitelist` to define a list of networks for which `once_received` checks should be excluded.

## Example

~~~ucl
once_received {
    good_host = "^mail";
    bad_host = "static";
    bad_host = "dynamic";
    symbol_strict = "ONCE_RECEIVED_STRICT";
    symbol = "ONCE_RECEIVED";
    whitelist = "/tmp/ip.map";
}
~~~

IP map can contain, as usually, IP's (both v4 and v6), networks (in CIDR notation) and optional comments starting from `#` symbol.
