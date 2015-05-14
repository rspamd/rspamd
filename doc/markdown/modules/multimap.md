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
* `ip map` - an effective radix trie of `ip/mask` values (supports both IPv4 and IPv6 addresses)
* `cdb` - constant database format (files only)

Multimap has different message attributes to be checked via maps.

## Configuration

The module itself contains a set of rules in form:

	symbol { type = type; map = uri; [optional params] }

Type attribute means what is matched with this map. The following types are supported:

* `ip` - matches source IP of message (radix map)
* `from` - matches envelope from (or header `From` if envelope from is absent)
* `rcpt` - matches any of envelope rcpt or header `To` if envelope info is missing
* `header` - matches any header specified (must have `header = "Header-Name"` configuration attribute)
* `dnsbl` - matches source IP against some DNS blacklist (see [RBL](rbl.md) documentation for details)

DNS maps has historic support.

Maps can also have a special URL format in style:
	
	map = "cdb:///path/to/file.cdb";

which is treated as CDB map by rspamd.

Here is an example configuration of multimap module:

~~~nginx
multimap {
	test { type = "ip"; map = "/tmp/ip.map"; symbol = "TESTMAP"; }
	spamhaus { type = "dnsbl"; map = "pbl.spamhaus.org"; symbol = "R_IP_PBL"; 
		description = "PBL dns block list"; } # Better use RBL module instead
}
~~~