---
layout: doc
title: Upgrading
---
# Updating Rspamd

This document describes incompatible changes introduced in recent Rspamd versions and details how to update your rules and configuration accordingly.

## Migrating to Rmilter 1.9.1 and Rspamd 1.3.1

Systemd socket activation has been removed in these releases. Rmilter may not restart correctly on upgrade on Debian platforms. Please run `systemctl restart rmilter` after installing the package if necessary. Rspamd is expected to restart correctly on upgrade. Both Rspamd & Rmilter should be automatically configured to run on reboot post-upgrade.

## Migrating from Rmilter 1.8 to Rmilter 1.9

There are couple of things that are no longer supported:

* beanstalk support has been removed from Rmilter in honor of Redis [pub/sub](http://redis.io/topics/pubsub), you must remove the whole `beanstalk` section from the configuration file
* auto whitelist for greylisting is no longer supported as it has been broken from the very beginning, you must remove all `awl` options from the greylisting section

If you have used beanstalk for some purposes then you could move to Redis [pub/sub](http://redis.io/topics/pubsub). There are settings for sending spam (`spam_servers` and `spam_channel`) and for sending messages copies (`copy_servers`, `copy_prob` and `copy_channel`) in the `redis` section that allow you to reproduce beanstalk functions using Redis.

Rmilter now supports configuration override from `rmilter.conf.local` and from `rmilter.conf.d/*.conf` files. You should consider using these methods for your local configuration options.

Rmilter no longer adds several SpamAssassin-compatible headers: namely `X-Spam-Status`, `X-Spam-Level` and `X-Spamd-Bar`. Support has been added for adding/removing custom headers under instruction of Rspamd (Requires Rspamd 1.3.0+). Example script which restores the removed headers is shown below (to be added to `/etc/rspamd/rspamd.local.lua`):

~~~lua
rspamd_config:register_symbol({
  name = 'RMILTER_HEADERS',
  type = 'postfilter',
  priority = 10,
  callback = function(task)
    local metric_score = task:get_metric_score('default')
    local score = metric_score[1]
    local required_score = metric_score[2]
    -- X-Spamd-Bar & X-Spam-Level
    local spambar
    local spamlevel = ''
    if score <= -1 then
      spambar = string.rep('-', score*-1)
    elseif score >= 1 then
      spambar = string.rep('+', score)
      spamlevel = string.rep('*', score)
    else
      spambar = '/'
    end
    -- X-Spam-Status
    local is_spam
    local spamstatus
    local action = task:get_metric_action('default')
    if action ~= 'no action' and action ~= 'greylist' then
      is_spam = 'Yes'
    else
      is_spam = 'No'
    end
    spamstatus = is_spam .. ', score=' .. string.format('%.2f', score)
    -- Add headers
    task:set_rmilter_reply({
      add_headers = {
        ['X-Spamd-Bar'] = spambar,
        ['X-Spam-Level'] = spamlevel,
        ['X-Spam-Status'] = spamstatus
      },
      remove_headers = {
        ['X-Spamd-Bar'] = 1,
        ['X-Spam-Level'] = 1,
        ['X-Spam-Status'] = 1
      }
    })
  end
})
~~~

## Migrating from Rspamd 1.2 to Rspamd 1.3

There are no incompatible changes introduced in Rspamd 1.3 version.

## Migrating from Rspamd 1.1 to Rspamd 1.2

There are no incompatible changes introduced in Rspamd 1.2 version.

## Migrating from Rspamd 1.0 to Rspamd 1.1

The only change here affects users with per-user statistics enabled. There is an incompatible change in `sqlite3` and per-user behaviour:

Now both `redis` and `sqlite3` follow common principles for per-user statistics:

* If per-user statistics is enabled check per-user tokens **ONLY**
* If per-user statistics is not enabled then check common tokens **ONLY**

If you need the old behaviour, then you need to use a separate classifier for per-user statistics, for example:

~~~ucl
    classifier {
        tokenizer {
            name = "osb";
        }
        name = "bayes_user";
        min_tokens = 11;
        backend = "sqlite3";
        per_language = true;
        per_user = true;
        statfile {
            path = "/tmp/bayes.spam.sqlite";
            symbol = "BAYES_SPAM_USER";
        }
        statfile {
            path = "/tmp/bayes.ham.sqlite";
            symbol = "BAYES_HAM_USER";
        }
    }
    classifier {
        tokenizer {
            name = "osb";
        }
        name = "bayes";
        min_tokens = 11;
        backend = "sqlite3";
        per_language = true;
        statfile {
            path = "/tmp/bayes.spam.sqlite";
            symbol = "BAYES_SPAM";
        }
        statfile {
            path = "/tmp/bayes.ham.sqlite";
            symbol = "BAYES_HAM";
        }
    }
~~~

## Migrating from Rspamd 0.9 to Rspamd 1.0

In Rspamd 1.0 the default settings for statistics tokenization have been changed to `modern`, meaning that tokens are now generated from normalized words and there are various improvements which are incompatible with the statistics model used in pre-1.0 versions. To use these new features you should either **relearn** your statistics or continue using your old statistics **without** new features by adding a `compat` parameter:

~~~ucl
classifier {
...
    tokenizer {
        compat = true;
    }
...
}
~~~

The recommended way to store statistics now is the `sqlite3` backend (which is incompatible with the old mmap backend):

~~~ucl
classifier {
    type = "bayes";
    tokenizer {
        name = "osb";
    }
    cache {
        path = "${DBDIR}/learn_cache.sqlite";
    }
    min_tokens = 11;
    backend = "sqlite3";
    languages_enabled = true;
    statfile {
        symbol = "BAYES_HAM";
        path = "${DBDIR}/bayes.ham.sqlite";
        spam = false;
    }
    statfile {
        symbol = "BAYES_SPAM";
        path = "${DBDIR}/bayes.spam.sqlite";
        spam = true;
    }
}
~~~

## Migrating from Rspamd 0.6 to Rspamd 0.7

### WebUI changes

The Rspamd web interface is now a part of the Rspamd distribution. Moreover, all static files are now served by Rspamd itself so you won't need to set up a separate web server to distribute static files. At the same time, the WebUI worker has been removed and the controller acts as WebUI+old_controller which allows it to work with both a web browser and the rspamc client. However, you might still want to set up a full-featured HTTP server in front of Rspamd to enable, for example, TLS and access controls.

Now there are two password levels for Rspamd: `password` for read-only commands and `enable_password` for data changing commands. If `enable_password` is not specified then `password` is used for both commands.

Here is an example of the full configuration of the Rspamd controller worker to serve the WebUI:

~~~ucl
worker {
	type = "controller";
	bind_socket = "localhost:11334";
	count = 1;
	password = "q1";
	enable_password = "q2";
	secure_ip = "127.0.0.1"; # Allows to use *all* commands from this IP
	static_dir = "${WWWDIR}";
}
~~~

### Settings changes

The settings system has been completely reworked. It is now a lua plugin that registers pre-filters and assigns settings according to dynamic maps or a static configuration. Should you want to use the new settings system then please check the recent [documentation]({{ site.url }}{{ site.baseurl }}/doc/configuration/settings.html). The old settings have been completely removed from Rspamd.

### Lua changes

There are many changes in the lua API and some of them are, unfortunately, breaking ones.

* many superglobals are removed: now Rspamd modules need to be loaded explicitly,
the only global remaining is `rspamd_config`. This affects the following modules:
	- `rspamd_logger`
	- `rspamd_ip`
	- `rspamd_http`
	- `rspamd_cdb`
	- `rspamd_regexp`
	- `rspamd_trie`

~~~lua
local rspamd_logger = require "rspamd_logger"
local rspamd_trie = require "rspamd_trie"
local rspamd_cdb = require "rspamd_cdb"
local rspamd_ip = require "rspamd_ip"
local rspamd_regexp = require "rspamd_regexp"
~~~

* new system of symbols registration: now symbols can be registered by adding new indices to `rspamd_config` object. Old version:

~~~lua
local reconf = config['regexp']
reconf['SYMBOL'] = function(task)
...
end
~~~

new one:

~~~lua
rspamd_config.SYMBOL = function(task)
...
end
~~~

`rspamd_message` is **removed** completely; you should use task methods to access message data. This includes such methods as:

* `get_date` - this method can now return a date for task and message based on the arguments:

~~~lua
local dm = task:get_date{format = 'message'} -- MIME message date
local dt = task:get_date{format = 'connect'} -- check date
~~~

* `get_header` - this function is totally reworked. Now `get_header` version returns just a decoded string, `get_header_raw` returns an undecoded string and `get_header_full` returns the full list of tables. Please consult the corresponding [documentation]({{ site.url }}{{ site.baseurl }}/doc/lua/task.html) for details. You also might want to update the old invocation of task:get_header to the new one.
Old version:

~~~lua
function kmail_msgid (task)
	local msg = task:get_message()
	local header_msgid = msg:get_header('Message-Id')
	if header_msgid then
		-- header_from and header_msgid are tables
		for _,header_from in ipairs(msg:get_header('From')) do
	    	...
		end
	end
	return false
end
~~~

new one:

~~~lua
function kmail_msgid (task)
	local header_msgid = task:get_header('Message-Id')
	if header_msgid then
		local header_from = task:get_header('From')
		-- header_from and header_msgid are strings
	end
	return false
end
~~~

or with the full version:

~~~lua
rspamd_config.FORGED_GENERIC_RECEIVED5 = function (task)
	local headers_recv = task:get_header_full('Received')
	if headers_recv then
		-- headers_recv is now the list of tables
		for _,header_r in ipairs(headers_recv) do
			if re:match(header_r['value']) then
				return true
			end
		end
	end
    return false
end
~~~

* `get_from` and `get_recipients` now accept optional numeric arguments that specifies where to get sender and recipients for a message. By default, this argument is `0` which means that data is initially checked in the SMTP envelope (meaning `MAIL FROM` and `RCPT TO` SMTP commands) and if the envelope data is inaccessible then it is grabbed from MIME headers. Value `1` means that data is checked on envelope only, while `2` switches mode to MIME headers. Here is an example from the `forged_recipients` module:

~~~lua
-- Check sender
local smtp_from = task:get_from(1)
if smtp_from then
	local mime_from = task:get_from(2)
	if not mime_from or
			not (string.lower(mime_from[1]['addr']) ==
			string.lower(smtp_from[1]['addr'])) then
		task:insert_result(symbol_sender, 1)
	end
end
~~~

### Protocol changes

Rspamd now uses `HTTP` protocols for all operations, therefore an additional client library is unlikely to be needed. The fallback to the old `spamc` protocol has also been implemented to be automatically compatible with `rmilter` and other software that uses the `rspamc` protocol.
