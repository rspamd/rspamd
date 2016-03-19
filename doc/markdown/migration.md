# Migrating between rspamd version

This document describes incompatible changes introduced in the recent rspamd 
versions. Here you can find information about how to overcome this incompatibilities
and update your rules and configuration according to these changes.

## Migrating from rspamd 1.0 to rspamd 1.1

This notice affects merely users with per-user statistics enabled. There is an incompatible change in sqlite3 and per_user behaviour:

Now both redis and sqlite3 follows the common principles for per-user statistics:

* If per-user statistics is enabled check per-user tokens **ONLY**
* If per-user statistics is not enabled then check common tokens **ONLY**

If you need old behaviour, then you'd need to use separate classifier
for per-user statistics, for example:

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

## Migrating from rspamd 0.9 to rspamd 1.0

In rspamd 1.0, the default settings for statistics tokenization has been changed to `modern`, meaning
that now tokens are generated from the normalized words and there are various improvements incompatible with the
statistics model used in pre 1.0 versions. Therefore, to use all these advantages you should either **relearn**
your statistics or continue using your old statistics **without** new features by adding `compat` parameter:

~~~ucl
classifier {
...
    tokenizer {
        compat = true;
    }
...
}
~~~

The recommended way to create statistics now is `sqlite3` backend (which is incompatible with old mmap backend however):

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

## Migrating from rspamd 0.6 to rspamd 0.7

### Webui changes

Rspamd web interface is now a part of distribution. Moreover, all static files
are now served by rspamd itself so you won't need to setup additional web server
to distribute static files. At the same time, webui worker is now removed and
the controller acts as webui+old_controller allowing to work with both web browser
and rspamc client. However, one might still want to setup a full-featured HTTP
server before rspamd to enable, for example TLS and access controls. 

Now there are two password levels for rspamd: `password` for read-only commands
and `enable_password` for data changing commands. If `enable_password` is not
specified then `password` is used for both commands.

Here is an example of the full configuration of rspamd controller worker to
serve webui:

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

Settings system has been completely reworked. It is now a lua plugin that
registers pre-filter and assign settings according to some dynamic map or
a static configuration. Should you want to use the new settings system then
please check the recent [documentation](https://rspamd.com/doc/configuration/settings.html).
The old settings have been completely removed from rspamd.

### Lua changes

There are many changes in lua API and some of them are unfortunately breaking ones.

* many superglobals are removed: now rspamd modules need to be loaded explicitly,
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

* new system of symbols registration: now symbols can be registered by adding
new indices to `rspamd_config` object. Old version:

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

`rspamd_message` is **removed** completely, you should use task methods to
access message's data. This includes such methods as:

* `get_date` - now this method can return date for task and message based on the arguments:

~~~lua
local dm = task:get_date{format = 'message'} -- MIME message date
local dt = task:get_date{format = 'connect'} -- check date
~~~
	
* `get_header` - this function is now totally reworked. Now `get_header` version
returns just a decoded string, `get_header_raw` returns undecoded string and
`get_header_full` returns the full list of tables. Please consult with the
corresponding [documentation](https://rspamd.com/doc/lua/task.html) for details.
You also might want to correct old invocation of task:get_header to new one.
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

* `get_from` and `get_recipients` now accepts optional numeric argument that
specifies where to get a sender and recipients for a message. By default this
argument is `0` which means that data is initially checked in SMTP envelope
(meaning `MAIL FROM` and `RCPT TO` SMTP commands) and if envelope data is
unaccessible then it is grabbed from MIME headers. Value `1` means that data
is checked on envelope only, whilst `2` switches mode to MIME headers. Here is
an example from `forged_recipients` module:

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

Rspamd now uses `HTTP` protocols for all operations, therefore an additional
client library is unlikely needed. The fallback to old `spamc` protocol has also
been implemented automatically to be compatible with `rmilter` and other software
that uses `rspamc` protocol.
