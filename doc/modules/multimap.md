---
layout: doc_modules
title: Multimap module
---
# Multimap module

Multimap module is designed to handle rules that are based on different types of lists that are dynamically updated by Rspamd and called `maps`. This module is useful for whitelists, blacklists and other lists to be organized via files. It can also load remote lists using `HTTP` and `HTTPS` protocols. This article explains in detail all configuration options and features of this module.

* TOC
{:toc}

## Principles of work

Maps in Rspamd are files or HTTP links that are automatically monitored and reloaded
if changed. For example, maps can be defined as following:

	"http://example.com/file"
	"file:///etc/rspamd/file.map"
	"/etc/rspamd/file.map"

Rspamd respects `304 Not Modified` reply from HTTP server allowing to save traffic
when a map has not been actually changed since last load. For file maps, Rspamd uses normal
`mtime` file attribute (time modified). The global map watching settings are defined in the
`options` section of the configuration file:

* `map_watch_interval`: defines time when all maps are rescanned; the actual check interval is jittered to avoid simultaneous checking (hence, the real interval is from this value up to the this interval doubled).

## Configuration

The module itself contains a set of rules in form:

~~~ucl
symbol { 
  type = "type"; 
  map = "url"; 
  # [optional params...] 
}
symbol1 { 
  type = "type"; 
  map = "from"; 
  # [optional params...] 
}

...
~~~

You can define new rules in the file `/etc/rspamd/local.d/multimap.conf`. 

Mandatory attributes are:

* `type` - map [type](#map-types)
* `map` - path to the file with list, for example:
  + `http://example.com/list` - HTTP map, reloaded using `If-Modified-Since`, can be signed
  + `https://example.com/list` - HTTPS map - same as HTTP but with TLS enabled (with certificate check)
  + `file:///path/to/list` - file map, reloaded on change, can be signed
  + `/path/to/list` - shorter form of a file map
  + `cdb://path/to/list.cdb` - [CDB](http://www.corpit.ru/mjt/tinycdb.html) map in file, cannot be signed

For header maps, you also need to specify the exact header using `header` option.

Lists can contain keys:

~~~
key1
key2
~~~

key-value pairs (for multi-symbols maps):

~~~
key1 value1
key2 value2
key3 value3:score
~~~

and comments:

~~~
key1
# Single line comment
key2 # Embedded comment
~~~

The last line of a map **must** have a newline symbol at the end.

Optional map configuration attributes:

* `prefilter` - defines if the map is used in [prefilter mode](#pre-filter-maps)
* `action` - for prefilter maps defines action set by map match
* `regexp` - set to `true` if your map contain [regular expressions](#regexp-maps)
* `symbols` - array of symbols that this map can insert (for key-value pairs), [learn more](#multiple-symbols-maps)
* `score` - score of the symbol (can be redefined in the `metric` section)
* `description` - map description
* `group` - group for the symbol (can be redefined in `metric`)
* `require_symbols` - expression of symbols that have to match for a specific message: [learn more](#conditional-maps)
* `filter` - match specific part of the input (for example, email domain): [here](#map-filters) is the complete definition of maps filters

## Map types

Type attribute means what is matched with this map. The following types are supported:

* `ip` - matches source IP of message (radix map)
* `from` - matches envelope from (or header `From` if envelope from is absent)
* `rcpt` - matches any of envelope rcpt or header `To` if envelope info is missing
* `header` - matches any header specified (must have `header = "Header-Name"` configuration attribute)
* `dnsbl` - matches source IP against some DNS blacklist (consider using [RBL](rbl.html) module for this)
* `url` - matches URLs in messages against maps
* `filename` - matches attachment filename against map
* `content` - matches specific content of a message (e.g. headers, body or even a full message) against some map, usually regular expressions map

DNS maps are legacy and are not encouraged to use in new projects (use [rbl](rbl.html) for that).

Maps can also be specified as [CDB](http://www.corpit.ru/mjt/tinycdb.html) databases which might be useful for large maps:

~~~ucl
SOME_SYMBOL {
    map = "cdb:///path/to/file.cdb";
    type = "from";
}
~~~

## Regexp maps

All maps with the exception of `ip` and `dnsbl` maps support `regexp` mode. In this mode, all keys in maps are treated as regular expressions, for example:

```
# Sole key
/example\d+\.com/i
# Key + value (test)
/other\d+\.com/i test
# Comments are still enabled
```

For performance considerations, use only expressions supported by [Hyperscan](http://01org.github.io/hyperscan/dev-reference/compilation.html#pattern-support) as this engine provides blazing performance at no additional cost. Currently, there is no way to distinguish what particular regexp was matched in case if multiple regexp were matched.

To enable regexp mode, you should set `regexp` option to `true`:

~~~ucl
# local.d/multimap.conf
SENDER_FROM_WHITELIST {
  type = "from";
  map = "file:///tmp/from.map";
  regexp = true;
}
~~~

## Map filters

It is also possible to apply a filtering expression before checking value against some map. This is mainly useful
for `header` rules. Filters are specified with `filter` option. Rspamd supports the following filters so far:

### From, rcpt and header filters

* `email` or `email:addr` - parse header value and extract email address from it (`Somebody <user@example.com>` -> `user@example.com`)
* `email:user` - parse header value as email address and extract user name from it (`Somebody <user@example.com>` -> `user`)
*  `email:domain` - parse header value as email address and extract domain part from it (`Somebody <user@example.com>` -> `example.com`)
*  `email:name` - parse header value as email address and extract displayed name from it (`Somebody <user@example.com>` -> `Somebody`)
* `regexp:/re/` - extracts generic information using the specified regular expression

### URL filters

URL maps allows another set of filters (by default, `url` maps are matched using hostname part):

* `tld` - matches TLD (top level domain) part of the URL
* `full` - matches the complete URL (not the hostname)
* `is_phished` - matches hostname but if and only if the URL is phished (e.g. pretended to be from another domain)
* `regexp:/re/` - extracts generic information using the specified regular expression from the hostname
* `tld:regexp:/re/` - extracts generic information using the specified regular expression from the TLD part
* `full:regexp:/re/` - extracts generic information using the specified regular expression from the full URL text

### Filename filters

Filename maps support this filters set:

* `extension` - matches file extension
* `regexp:/re/` - extract data from filename according to some regular expression

### Content filters

Content maps support the following filters:

* `body` - raw undecoded body content (with the exceptions of headers)
* `full` - raw undecoded content of a message (including headers)
* `headers` - undecoded headers
* `text` - decoded and converted text parts (without HTML tags but with newlines)
* `rawtext` - decoded but not converted text parts (with HTML tags and newlines)
* `oneline` - decoded and stripped text content (without HTML tags and newlines)

## Pre-filter maps

To enable pre-filter support, you should specify `action` parameter which can take one of the
following values:

* `accept` - accept the message (no action)
* `add header` or `add_header` - add a header to the message
* `rewrite subject` or `rewrite_subject` - change the subject
* `greylist` - greylist the message
* `reject` - drop the message

No filters will be processed for a message if such a map matches. Multiple symbols or symbol conditions are not supported for prefilter maps by design.

~~~ucl
# local.d/multimap.conf
IP_WHITELIST { 
  type = "ip"; 
  map = "/tmp/ip.map"; 
  prefilter = true;
  action = "accept";
}
# Better use RBL module instead
SPAMHAUS_PBL_BLACKLIST { 
  type = "dnsbl"; 
  map = "pbl.spamhaus.org";
  description = "PBL dns block list";
  prefilter = true;
  action = "reject";
}
~~~

## Multiple symbol maps

From the version 1.3.1, it is possible to define multiple symbols and scores using multimap module. To do that, you should define all possible symbols using `symbols` option in multimap:

~~~ucl
# local.d/multimap.conf
CONTENT_BLACKLISTED {
  type = "content";
  filter = "body"; # can be headers, full, oneline, text, rawtext
  map = "/${LOCAL_CONFDIR}/content.map";
  symbols = ["CONTENT_BLACKLISTED1", "CONTENT_BLACKLISTED2"];
  regexp = true;
}
~~~

In this example, you can use 3 symbols:

* CONTENT_BLACKLISTED
* CONTENT_BLACKLISTED1
* CONTENT_BLACKLISTED2

the map:

~~~
# Symbol + score
/re1/ CONTENT_BLACKLISTED1:10
# Symbol with default score
/re2/ CONTENT_BLACKLISTED2
# Just a default symbol: CONTENT_BLACKLISTED
/re3/
~~~

Symbols that are not defined in the `symbols` attribute but used in the map are ignored and replaced by the default map symbol. If the value of a key-value pair is missing, then Rspamd just inserts the default symbol with dynamic weight equal to `1.0` (which is multiplied by metric score afterwards).

## Conditional maps

From version 1.3.1, it is possible to set up maps that depends on other rules and check map if some certain condition is satisfied. In particular, you can check that a message has a valid `SPF` policy to perform some whitelisting. However, you don't want to bother about mailing lists. Then you can write the following map condition:

~~~ucl
# local.d/multimap.conf
FROM_WHITELISTED {
  require_symbols = "R_SPF_ALLOW & !MAILLIST";
  type = "from";
  map = "/some/list";
}
~~~

You can use any logic expression of other symbols within `require_symbols` definition. Rspamd automatically inserts dependency for a multimap rule on all symbols that are required by this particular rule. You cannot use symbols added by post-filters here, however, pre-filter and normal filter symbols are allowed.

## Examples

Here are some examples of multimap configurations:

~~~ucl
# local.d/multimap.conf
SENDER_FROM_WHITELIST_USER {
  type = "from";
  filter = "email:user";
  map = "file:///tmp/from.map";
  action = "accept"; # Prefilter mode
}
SENDER_FROM_REGEXP {
  type = "header";
  header = "from";
  filter = "regexp:/.*@/";
  map = "file:///tmp/from_re.map";
}
URL_MAP {
  type = "url";
  filter = "tld";
  map = "file:///tmp/url.map";
}
URL_MAP_RE {
  type = "url";
  filter = "tld:regexp:/\.[^.]+$/"; # Extracts the last component of URL
  map = "file:///tmp/url.map";
}
FILENAME_BLACKLISTED {
  type = "filename";
  filter = "extension";
  map = "/${LOCAL_CONFDIR}/filename.map";
  action = "reject";
}
CONTENT_BLACKLISTED {
  type = "content";
  filter = "body"; # can be headers, full, oneline, text, rawtext
  map = "/${LOCAL_CONFDIR}/content.map";
  symbols = ["CONTENT_BLACKLISTED1", "CONTENT_BLACKLISTED2"];
  regexp = true;
}
~~~
