# Rspamd modules

Rspamd ships with a set of modules. Some modules are written in C to speedup
complex procedures while others are written in lua to reduce code size.
Actually, new modules are encouraged to be written in lua and add the essential
support to the Lua API itself. Truly speaking, lua modules are very close to 
C modules in terms of performance. However, lua modules can be written and loaded
dynamically.

## C Modules

C modules provides core functionality of rspamd and are actually statically linked
to the main rspamd code. C modules are defined in the `options` section of rspamd
configuration. If no `filters` attribute is defined then all modules are disabled.
The default configuration enables all modules explicitly:

~~~nginx
filters = "chartable,dkim,spf,surbl,regexp,fuzzy_check";
~~~

Here is the list of C modules available:

- [regexp](regexp.md): the core module that allow to define regexp rules,
rspamd internal functions and lua rules.
- [surbl](surbl.md): this module extracts URLs from messages and check them against
public DNS black lists to filter messages with malicious URLs.
- [spf](spf.md): checks SPF records for messages processed.
- [dkim](dkim.md): performs DKIM signatures checks.
- [fuzzy_check](fuzzy_check.md): checks messages fuzzy hashes against public blacklists.
- [chartable](chartable.md): checks character sets of text parts in messages.

## Lua modules

Lua modules are dynamically loaded on rspamd startup and are reloaded on rspamd
reconfiguration. Should you want to write a lua module consult with the 
[Lua API documentation](../lua/). To define path to lua modules there is a special section
named `modules` in rspamd:

~~~nginx
modules {
  path = "/path/to/dir/";
  path = "/path/to/module.lua";
  path = "$PLUGINSDIR/lua";
}
~~~

If a path is a directory then rspamd scans it for `*.lua" pattern and load all
files matched.

Here is the list of Lua modules shipped with rspamd:

- [multimap](multimap.md) - a complex module that operates with different types
of maps.
- [rbl](rbl.md) - a plugin that checks messages against DNS blacklist based on
either SMTP FROM addresses or on information from `Received` headers.
- [emails](emails.md) - extract emails from a message and checks it against DNS
blacklists.
- [maillist](maillist.md) - determines the common mailing list signatures in a message.
- [once_received](once_received.md) - detects messages with a single `Received` headers
and performs some additional checks for such messages.
- [phishing](phishing.md) - detects messages with phished URLs.
- [ratelimit](ratelimit.md) - implements leaked bucket algorithm for ratelimiting and
uses `redis` to store data.
- [trie](trie.md) - uses suffix trie for extra-fast patterns lookup in messages.