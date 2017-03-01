---
layout: doc_conf
title: Users settings description
---
# Rspamd user settings

## Introduction

Rspamd can apply different settings for messages scanned. Each setting can define a set of custom metric weights, symbols or actions scores and enable or disable certain checks. Rspamd settings can be loaded as dynamic maps and updated automatically if a corresponding file or URL has changed since its last update.

To load settings as a dynamic map, you can set 'settings' to a map string:

~~~ucl
settings = "http://host/url"
~~~

If you don't want dynamic updates then you can define settings as an object:

~~~ucl
settings {
	setting1 = {
	...
	}
	setting2 = {
	...
	}
}
~~~

Alternatively, settings could be passed to Rspamd by a client by query parameter:

~~~
GET /symbols?settings="{symbol1 = 10.0}" HTTP/1.0
~~~

or HTTP header

~~~
GET /symbols HTTP/1.0
Settings: {symbol1 = 10.0}
~~~

Settings could also be indexed by ID, allowing to select a specific setting without checking for its conditions. For example, this feature could be used to split inbound and outbound mail flows by specifying different rules set from the MTA side. Another use case of settings id option is to create a dedicated lightweight checks for certain conditions, for example DKIM checks.

Let's assume that we have the following settings in the configuration that have id `dkim`:

~~~ucl
settings {
	id = "dkim";
	dkim {
		enable_groups = ["dkim"];
	}
}
~~~

Afterwards, if we send a request with this settings id using HTTP protocol:

~~~
GET /symbols HTTP/1.0
Settings-ID: dkim
~~~

then Rspamd won't check all rules but DKIM ones. Alternatively, you could check this setup using `rspamc` command:

~~~
rspamc --header="settings-id=dkim" message.eml
~~~

## Settings structure

The settings file should contain a single section called "settings":

~~~ucl
settings {
	some_users {
		id = "some_users";
		priority = high;
		from = "@example.com";
		rcpt = "admin";
		rcpt = "/user.*/";
		ip = "172.16.0.0/16";
		user = "@example.net";
		apply "default" {
			symbol1 = 10.0;
			symbol2 = 0.0;
			actions {
				reject = 100.0;
				greylist = 10.0;
				"add header" = 5.0; # Please note the space, NOT an underscore
			}
		}
		# Always add these symbols when settings rule has matched
		symbols [
			"symbol2", "symbol4"
		]
	}
	whitelist {
		priority = low;
		rcpt = "postmaster@example.com";
		want_spam = yes;
	}
	# Disable some checks for authenticated users
	authenticated {
		priority = high;
		authenticated = yes;
		apply "default" {
			groups_disabled = ["rbl", "spf"];
		}
	}
}
~~~

So each setting has the following attributes:

- `name` - section name that identifies this specific setting (e.g. `some_users`)
- `priority` - `high` (3), `medium` (2), `low` (1) or any non-zero integer value (default priority is `low`). Rules with greater priorities are matched first. From version 1.4 Rspamd checks rules with equal priorities in **alphabetical** order. Once a rule matches only that rule is applied and the rest are ignored.
- `match list` - list of rules which this rule matches:
	+ `from` - match SMTP from
	+ `rcpt` - match RCPT
	+ `ip` - match source IP address
	+ `user` - matches authenticated user ID of message sender if any
	+ `authenticated` - matches any authenticated user
- `apply` - list of applied rules, identified by metric name (e.g. `default`)
	+ `symbol` - modify weight of a symbol
	+ `actions` - defines actions
	+ `symbols_enabled` - array of symbols that should be checked (all other rules are disabled)
	+ `groups_enabled` - array of rules groups that should be checked (all other rules are disabled)
	+ `symbols_disabled` - array of disabled checks by symbol name (all other rules are enabled)
	+ `groups_disabled` - array of disabled checks by group name (all other rules are enabled)
- `symbols` - add symbols from the list if a rule has matched

If `symbols_enabled` or `groups_enabled` are found in `apply` element, then Rspamd disables all checks with the exception of the enabled ones. When `enabled` and `disabled` options are both presented, then the precedence of operations is the following:

1. Disable all symbols
2. Enable symbols from `symbols_enabled` and `groups_enabled`
3. Disable symbols from `symbols_disabled` and `groups_disabled`

Currently, you cannot mix several settings for a single message.

### Settings match

The match section performs `AND` operation on different matches: for example, if you have `from` and `rcpt` in the same rule, then the rule matches only when `from` `AND` `rcpt` match. For similar matches, the `OR` rule applies: if you have multiple `rcpt` matches, then *any* of these will trigger the rule. If a rule is triggered then no more rules are matched.

By default, regular expressions are case-sensitive. This can be changed with the `i` flag. String comparisons are case-insensitive.

Regexp rules can be slow and should not be used extensively.

The picture below describes the architecture of settings matching.

<img class="img-responsive" width="50%" src="{{ site.baseurl }}/img/settings.png">
