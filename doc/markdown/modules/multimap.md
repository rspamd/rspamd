# Multimap module

Multimap module is designed to handle rules that are based on different types of maps.

## Principles of work

Maps in rspamd are the files or HTTP links that are automatically monitored and reloaded
if changed. For example, maps can be defined as following:

	"http://example.com/file"
	"file:///etc/rspamd/file.map"
	"/etc/rspamd/file.map"

Rspamd respects `304 Not Modified` reply from HTTP server allowing to save traffic
when a map has not been actually changed since last load. For file maps, rspamd uses normal
`mtime` attribute (time modified). The global map watching settings are defined in the
`options` section of the configuration file:

* `map_watch_interval`: defines time when all maps are rescanned; the actual check interval is jittered to avoid simultaneous checking (hence, the real interval is from this value up to the this interval doubled).

Multimap module allows to build rules based on the dynamic maps content. Rspamd supports the following
map types in this module:

* `hash map` - a list of domains or `user@domain`
* `regexp map` - a list of regular expressions
* `ip map` - an effective radix trie of `ip/mask` values (supports both IPv4 and IPv6 addresses)
* `cdb` - constant database format (files only)

Multimap has different message attributes to be checked via maps.


Multimap can also be used for pre-filtering of message: so if map matches then no further checks will be performed. This feature is particularly useful for whitelisting, blacklisting and allows to save scan resources. To enable this mode just add `action` option to the map configuration (see below).

## Configuration

The module itself contains a set of rules in form:

	symbol { type = type; map = uri; [optional params] }

### Map types

Type attribute means what is matched with this map. The following types are supported:

* `ip` - matches source IP of message (radix map)
* `from` - matches envelope from (or header `From` if envelope from is absent)
* `rcpt` - matches any of envelope rcpt or header `To` if envelope info is missing
* `header` - matches any header specified (must have `header = "Header-Name"` configuration attribute)
* `dnsbl` - matches source IP against some DNS blacklist (consider using [RBL](rbl.md) module for this)
* `url` - matches URLs in messages against maps
* `filename` - matches attachment filename against map

DNS maps are legacy and are not encouraged to use in new projects (use [rbl](rbl.md) for that).

Maps can also be specified as [CDB](http://www.corpit.ru/mjt/tinycdb.html) databases which might be useful for large maps:

	map = "cdb:///path/to/file.cdb";

### Pre-filter maps

To enable pre-filter support, you should specify `action` parameter which can take the
following values:

* `accept` - accept a message (no action)
* `add header` or `add_header` - adds a header to message
* `rewrite subject` or `rewrite_subject` - change subject
* `greylist` - greylist message
* `reject` - drop message

No filters will be processed for a message if such a map matches.

~~~ucl
multimap {
	test { type = "ip"; map = "/tmp/ip.map"; symbol = "TESTMAP"; }
	spamhaus { type = "dnsbl"; map = "pbl.spamhaus.org"; symbol = "R_IP_PBL";
		description = "PBL dns block list"; } # Better use RBL module instead
}
~~~

### Regexp maps


All maps but `ip` and `dnsbl` support `regexp` mode. In this mode, all keys in maps are treated as regular expressions, for example:

	/example\d+\.com/i
	/other\d+\.com/i test
	# Comments are still enabled

For performance considerations, use only expressions supported by [hyperscan](http://01org.github.io/hyperscan/dev-reference/compilation.html#pattern-support) as this engine provides blazing performance at no additional cost. Currently, there is no way to distinguish what particular regexp was matched in case if multiple regexp were matched.

To enable regexp mode, you should set `regexp` option to `true`:

~~~ucl
sender_from_whitelist_user {
  type = "from";
  map = "file:///tmp/from.map";
  symbol = "SENDER_FROM_WHITELIST";
  regexp = true;
}
~~~

### Map filters

It is also possible to apply a filtering expression before checking value against some map. This is mainly useful
for `header` rules. Filters are specified with `filter` option. Rspamd supports the following filters so far:

* `email` or `email:addr` - parse header value and extract email address from it (`Somebody <user@example.com>` -> `user@example.com`)
* `email:user` - parse header value as email address and extract user name from it (`Somebody <user@example.com>` -> `user`)
*  `email:domain` - parse header value as email address and extract user name from it (`Somebody <user@example.com>` -> `example.com`)
*  `email:name` - parse header value as email address and extract displayed name from it (`Somebody <user@example.com>` -> `Somebody`)
* `regexp:/re/` - extracts generic information using the specified regular expression

URL maps allows another set of filters (by default, url maps are matched using hostname part):

* `tld` - matches TLD (top level domain) part of urls
* `full` - matches the complete URL not the hostname
* `is_phished` - matches hostname but if and only if the URL is phished (e.g. pretended to be from another domain)
* `regexp:/re/` - extracts generic information using the specified regular expression from the hostname
* `tld:regexp:/re/` - extracts generic information using the specified regular expression from the TLD part
* `full:regexp:/re/` - extracts generic information using the specified regular expression from the full URL text

Filename maps support this filters set:

* `extension` - matches file extension
* `regexp:/re/` - extract data from filename according to some regular expression

Here are some examples of pre-filter configurations:

~~~ucl
sender_from_whitelist_user {
  type = "from";
  filter = "email:user";
  map = "file:///tmp/from.map";
  symbol = "SENDER_FROM_WHITELIST_USER";
  action = "accept"; # Prefilter mode
}
sender_from_regexp {
  type = "header";
  header = "from";
  filter = "regexp:/.*@/";
  map = "file:///tmp/from_re.map";
  symbol = "SENDER_FROM_REGEXP";
}
url_map {
  type = "url";
  filter = "tld";
  map = "file:///tmp/url.map";
  symbol = "URL_MAP";
}
url_tld_re {
  type = "url";
  filter = "tld:regexp:/\.[^.]+$/"; # Extracts the last component of URL
  map = "file:///tmp/url.map";
  symbol = "URL_MAP_RE";
}
filename_blacklist {
  type = "filename";
  filter = "extension";
  map = "/${LOCAL_CONFDIR}/filename.map";
  symbol = "FILENAME_BLACKLISTED";
  action = "reject";
}
~~~
