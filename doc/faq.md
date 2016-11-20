---
layout: doc_faq
title: Frequently asked questions
---

# Frequently asked questions

This document includes some questions and practical examples that are frequently asked by Rspamd users.

## General questions

### Where to get help about Rspamd
The most convenient place for asking questions about Rspamd is the IRC channel _#rspamd_ on [http://freenode.net](http://freenode.net). For more information you can also check the [support page](https://rspamd.com/support.html)

### How to figure out why Rspamd process crashed
Like other programs written in `C` language, the best way to debug these problems is to obtain `core` dump. Unfortunately, there is no universal solution suitable for all platforms, however, for FreeBSD and Linux you could do the following:

First of all, you need to create a special directory for core files that will be writeable by all users on the system:

```
mkdir /coreland
chmod 1777 /coreland
```

For FreeBSD you can have either one core for all processes by setting:

```
sysctl kern.corefile=/coreland/%N.core
```

or a separate core for each crash (that includes PID of process):

```
sysctl kern.corefile=/coreland/%N-%p.core
```

For Linux this setting is slightly different:

```
sysctl kernel.core_pattern = /coreland/%e.core
```

or (with PID)

```
sysctl kernel.core_pattern = /coreland/%e-%p.core
```

Additional settings:

```
sysctl kernel.core_uses_pid = 1
sysctl fs.suid_dumpable = 2
```

The first one adds the PID to core file name, and the second allows setuid processes to be dumped. A good idea is to add these settings to `/etc/sysctl.conf` and then run `sysctl -p` to apply them.

#### Setting system limits

In distros with traditional SysV init, you can use the service init file, for example `/etc/init.d/rspamd` to permit dumping of core files by setting the appropriate resource limit. You will need to add the following line:

```
ulimit -c unlimited
```

just after the heading comment.
On FreeBSD you can use the file `/usr/local/etc/rc.d/rspamd` in the same way.

A good way to test the core files setup is sending a `SIGILL` signal to a process. For example, run `pkill --signal 4 rspamd` or `kill -s 4 <YOUR_PID>` and then check the `/coreland` directory for a core dump.

#### Systemd notes

On a distro with systemd (most mainstream Linux distros), things are a bit different.
First, you will need to edit the file `/etc/systemd/system.conf` and uncomment the `DefaultLimitCORE` parameter to enable systemd core dumps:

```
DefaultLimitCORE=infinity
```

After this, you will need to run `systemctl daemon-reload` to reread the configuration followed by `systemctl daemon-reexec` to apply it.

The more information about core dumps and systemd could be found here: <https://wiki.archlinux.org/index.php/Core_dump>

### How to limit number of core files
Rspamd can stop dumping cores upon reaching a specific limit. To enable this functionality you can add the following lines to the `etc/rspamd/local.d/options.inc`:

```ucl
cores_dir = "/coreland/";
max_cores_size = 1G;
```

That will limit the combined size of files in the `/coreland/` directory to 1 gigabyte. After reaching this limit, Rspamd will stop dumping core files. (Please note that Rspamd cannot distinguish its own core files from other core files in a system.)

### What can I do with core files
In most cases, it is enough to open core file with `gdb`  or another debugger, such as `lldb`:

```
gdb `which rspamd` -c /coreland/rspamd.core
lldb `which rspamd` -c /coreland/rspamd.core
```

If a core file has been opened without errors then you can type `bt full` in the debugger command line to get the full stack trace that caused this particular error.

### Why can I have different results for the same message
If your message has gained a `reject` score, Rspamd will stop further checks to save resources. However, some checks, such as network checks, could still occur as they might be started before reaching this threshold for the message. Therefore, sometimes you might see different (but all greater than or equal to the `reject` threshold) results for the same message. To avoid this behaviour you can set the HTTP header

```
Pass: all
```

when making a request to Rspamd (which is equal to `-p` flag for `rspamc` client).

Another possible reason for different results is too low a DNS, or task, timeout setting so asynchronous rules can't get results before being killed by a timeout. To get help about the relevant options you can type the following commands:

```
rspamadm confighelp options.DNS
rspamadm confighelp options.dns_max_requests
rspamadm confighelp workers.normal.task_timeout
```

and more generally:

```
rspamadm confighelp -k timeout
```

### What is the difference between `rspamc` and `rspamadm`
rspamadm is an administration tool that works with the **local** Rspamd daemon via a unix socket and performs management tasks. You can get help for this tool, and its options, by typing:

```
rspamadm help
rspamadm help <command>
```

rspamc is a client for an Rspamd remote daemon. It can communicate with an Rspamd scanner process or Rspamd controller process using the HTTP (with optional encryption) protocol, getting and displaying the results. It can do tasks such as scanning, learning and getting statistics:

```
rspamc message.eml # Scan a message
rspamc learn_spam message.eml # Learn message
rspamc -f 1 -w 10 fuzzy_add message.eml # Add message to fuzzy storage
```

### How does Rspamd support different characters sets

By default, Rspamd converts all messages to `UTF-8` encoding. This includes text parts (both `text/plain` and `text/html`), headers and MIME elements (boundaries, filenames). If there is no information on how to convert something to `UTF-8` - for example, when there is no `charset` attribute in the `Content-Type` header or if there are some broken `UTF-8` characters - then Rspamd treats this text as raw for safety considerations. The difference between raw and `UTF-8` text is that for `UTF-8` it is possible to use unicode regular expressions by specifying the `/U` flag. For raw texts, Rspamd uses raw complementary expressions, which may lack some features.

It is always safe to assume that everything will be encoded in `UTF-8`; even in the case of raw messages, you would just miss some particular features. There is also a module called [chartable](https://rspamd.com/doc/modules/chartable.html) that checks for different unicode (or `ASCII` - non `ASCII` characters in raw mode) symbols and tries to guess if there is an attempt to mix characters sets.

### Can I relearn messages for fuzzy storage or for statistics

In case you need to move a hash from one list (e.g. blacklist) to another (e.g. whitelist), you need to call the `rspamc fuzzy_del` command for the first list (lists are identified by number) followed by `rspamc fuzzy_add` command:

```
rspamc -f 1 fuzzy_del message.eml
rspamc -f 2 -w <weight> fuzzy_add message.eml
```

If you just need to increase a score, then call `fuzzy_add` with the score change. (It is not possible to decrease a score, however.)

Statistics are treated a bit differently. Rspamd keeps hashes of tokens learned in a special storage called the `learn_cache`. If Rspamd finds that a particular token combination has been learned already it does the following:

* if the class of tokens is the same (e.g. spam and spam) then Rspamd just refuses to learn these tokens again
* otherwise, Rspamd performs so-called `relearning`:
    + scores in the current class are decreased for this token set
    + scores in the opposite class are increased for this token set
    + the class of tokens in the learn cache is updated accordingly

All these actions are performed automatically if `learn_cache` is enabled. (It is highly recommended to enable this setting, as repeated learnings will affect the performance of the statistical module.)


### Why do some symbols have different scores for different messages

Rspamd supports so-called `dynamic` symbols. A metric score is multiplied by some value (that is usually in the range `[0..1]`) and added to the scan result. For example, the Bayes classifier adds a score based on probability:

* if the probability is close to `50%` then the score is very close to 0
* if the probability is higher `[50% .. 75%]` then the score increases gradually
* when the probability is closer to `90%` the symbol's score is close to 0.95 and on `100%` it is exactly 1.0
* this logic is reversed for HAM probability (from `50%` to `0%` spam probability)

Many Rspamd rules, such as `PHISHING` and fuzzy checks, use dynamic scoring.

### Can I check a message with Rspamd without rspamc

```
curl --data-binary @- http://localhost:11333/symbols < file.eml
```

### How is Rspamd spelled and capitalized?

Rspamd as a spam-filtering system or as a project is spelled with a capital `R` followed by a lower-case `spamd`, but when referring to the process or application it is not capitalized.

## Configuration questions

### What are Rspamd actions

Unlike SpamAssassin, Rspamd **suggests** the desired action for a specific message scanned:

- `reject`: ultimately reject message
- `rewrite subject`: set spam subject
- `add header`: add spam header
- `greylist`: delay message for a while
- `no action`: pass message

Rspamd itself **does not** alter a message, that is a task for the MTA or any shim agent (e.g. [Rmilter](https://rspamd.com/rmilter/)). All actions but `reject` and `no action` could be treated as `potential spam` and greylisted or moved to a `Junk` folder for the user.

### What are local and override config files
Historically, Rspamd provided user-editable configuration files. However, as the project developed, it became clear that this idea had drawbacks: Rspamd configuration influences the overall filtering quality, performance and other important metrics and it was difficult to maintain local configurations with new releases of Rspamd. Hence, I decided to add two possibilities:

1. Override configurations
2. Local configurations

An override configuration (`etc/rspamd.conf.override`) is used to ultimately redefine the default values in Rspamd. In this file, you can redefine **whole sections** of the default configuration. For example, if you have a module `example` defined in the default configuration as follows:

```ucl
example {
  option1 = "value";
  option2 = true;
}
```

and you wanted to override `option2` by adding the following to `etc/rspamd.conf.override`:

```ucl
example {
  option2 = false;
}
```

this might work unexpectedly: the new config would have an `example` section with a single key `option2`, while `option1` would be ignored. The global local file, namely `rspamd.conf.local`, has the same limitation: you can add your own configuration there but you should **NOT** redefine anything from the default configuration there or it will just be ignored. The only exception to this rule is the _metric_ section. So you could use something like:

```ucl
metric "default" {
  symbol "MY_SYMBOL" {
    score = 10.0;
    description = "my rule";
  }
}
```

and add this to the `rspamd.conf.local` (but not override).

### What are the local.d and override.d directories
From Rspamd version 1.2 onwards, the default configuration provides two more ways to extend or redefine each configuration file shipped with Rspamd. Each section definition includes two files with different priorities:

- `etc/rspamd/local.d/<conf_file>` - included with priority `1` that allows you to redefine and extend the default rules; but `dynamic updates` or items redefined via the WebUI will have higher priority and can redefine the values included
- `etc/rspamd/override.d/<conf_file>` - included with priority `10` that allows you to redefine all other things that could change configuration in Rspamd

Another important difference from the global override and local rules is that these files are included within each section. Here is an example of utilizing local.d for the `modules.d/example.conf` configuration file:

```ucl
example {
  # WebUI include
  .include(try=true,priority=5) "${DBDIR}/dynamic/example.conf"
  # Local include
  .include(try=true,priority=1) "$LOCAL_CONFDIR/local.d/example.conf"
  # Override include
  .include(try=true,priority=10) "$LOCAL_CONFDIR/override.d/example.conf"
  option1 = "value";
  option2 = true;
}
```

in `local.d/example.conf`:

```ucl
option2 = false;
option3 = 1.0;
```

in `override.d/example.conf`:

```ucl
option3 = 2.0;
option4 = ["something"];
```

and the target configuration (that you could see using `rspamadm configdump example`):

```ucl
example {
  option1 = "value"; # From default settings
  option2 = false; # From local.d
  option3 = 2.0; # Local is overrided by override
  option4 = ["something"]; # From override.d
}
```

Here is another example with more complicated structures inside. Here is the original configuration:

```ucl
# orig.conf
rule "something" {
  key1 = value1;
  key2 = {
    subkey1 = "subvalue1";
  }
}
rule "other" {
  key3 = value3;
}
```

and there is some `local.d/orig.conf` that looks like this:

```ucl
# local.d/orig.conf
rule "something" {
  key1 = other_value; # overwrite "value1"
  key2 = {
    subkey2 = "subvalue2"; # append new value
  }
}
rule "local" { # add new rule
  key_local = "value_local";
}
```

then we will have the following merged configuration:

```ucl
# config with local.d/orig.conf
rule "something" {
  key1 = other_value; # from local
  key2 = {
    subkey1 = "subvalue1";
    subkey2 = "subvalue2"; # from local
  }
}
rule "other" {
  key3 = value3;
}
rule "local" { # from local
  key_local = "value_local";
}
```

If you have the same config but in `override.d` directory, then it will **completely** override all rules defined in the original file:

```ucl
# config with override.d/orig.conf
rule "something" {
  key1 = other_value;
  key2 = {
    subkey2 = "subvalue2";
}
rule "local" {
  key_local = "value_local";
}
```

This looks complicated but it allows smoother updates and simplifies automatic management. If you are unsure about your configuration, then take a look at the output of the `rspamadm configdump` command, which displays the target configuration with many options available, and the `rspamadm confighelp` command which shows help for many Rspamd options.

### What are rspamd.conf.local and rspamd.conf.override

While `override.d` and `local.d` replace entries inside block elements, `rspamd.conf.local` and `rspamd.conf.override` operate on whole blocks (`{}`).

What distinguishes these files is the way in which they alter the configuration - `rspamd.conf.local` adds or merges config elements (and is useful, for example, for setting custom metrics) while `rspamd.conf.override` adds or replaces config elements (and is useful for redefining settings completely).

### What are maps
Maps are files that contain lists of keys or key-value pairs that could be dynamically reloaded by Rspamd when changed. The important difference to configuration elements is that map reloading is done 'live' without and expensive restart procedure. Another important thing about maps is that Rspamd can monitor both file and HTTP maps for changes (modification time for files and HTTP `If-Modified-Since` header for HTTP maps). So far, Rspamd supports `HTTP` and `file` maps.

### What can be in the maps

Maps can have the following objects:

- spaces and one line comments started by `#` symbols
- keys
- optional values separated by a space character
- keys with spaces enclosed in double quotes
- keys with slashes (regular expressions) enclosed in slashes
- IP addresses with optional mask

Here are some examples:

```
key1 # Single key
# Comment ignored

# Empty line ignored
key2 1 # Key and value
"key3 with space"
"key with \" escaped" value with spaces
```

Regexp maps:

```
/regexp/i
/regexp/is some other value
```

IP maps:

```
192.168.0.1 # Mask is /32
[::1] # Mask is /128
[::1]/64
192.168.0.1/19
```

### How to sign maps
From Rspamd version 1.2 onwards, each map can have a digital signature using the `EdDSA` algorithm. To sign a map you can use `rspamadm signtool` and to generate a signing keypair - `rspamadm kyypair -s -u`:

```ucl
keypair {
   pubkey = "zo4sejrs9e5idqjp8rn6r3ow3x38o8hi5pyngnz6ktdzgmamy48y";
   privkey = "pwq38sby3yi68xyeeuup788z6suqk3fugrbrxieri637bypqejnqbipt1ec9tsm8h14qerhj1bju91xyxamz5yrcrq7in8qpsozywxy";
   id = "bs4zx9tcf1cs5ed5mt4ox8za54984frudpzzny3jwdp8mkt3feh7nz795erfhij16b66piupje4wooa5dmpdzxeh5mi68u688ixu3yd";
   encoding = "base32";
   algorithm = "curve25519";
   type = "sign";
}
```

Then you can use `signtool` to edit the map file:

```
rspamadm signtool -e --editor=vim -k <keypair_file> <map_file>
```

To enforce signing policies you should add a `sign+` string to your map definition:

```
map = "sign+http://example.com/map"
```

To specify the trusted key you could either put the **public** key from the keypair in the `local.d/options.inc` file as following:

```
trusted_keys = ["<public key string>"];
```

or add it as a `key` definition in the map string:

```
map = "sign+key=<key_string>+http://example.com/map"
```

### What are one-shot rules

In Rspamd, each rule can be triggered multiple times. For example, if a message has 10 URLs and 8 of them are in some URL blacklist (based on their unique tld), then Rspamd would add a URIBL rule 8 times for this message. Sometimes, that's not a desired behaviour - in that case just add `one_shot = true` to the symbol's definition in the metric for that symbol and the symbol won't be added multiple times.

### What is the use of symbol groups

Symbol groups are intended to group similar rules. This is most useful when group names are used in composite expressions such as `gr:<group_name>`. It is also possible to set a joint limit for the score of a specific group:

```ucl
group "test" {
  symbol "test1" {
    score = 10;
  }
  symbol "test2" {
    score = 20;
  }

  max_score = 15;
}
```

In this case, if `test1` and `test2` both match, their joint score won't be more than `15`.

### Why are some symbols missing in the metric configuration

It is now possible to set up rules completely using Lua. This allows setting all necessary attributes without touching the configuration files. However, it is still possible to override the default scores in any configuration file. Here is an example of such a rule:

~~~lua
rspamd_config.LONG_SUBJ = {
  callback = function(task)
    local sbj = task:get_header('Subject')
    if sbj and util.strlen_utf8(sbj) > 200 then
      return true
    end
    return false
  end,

  score = 3.0,
  group = 'headers',
  description = 'Subject is too long'
}
~~~

You can use the same approach when writing rules in `rspamd.local.lua`.

### How can I disable some Rspamd rules safely

The best way is to add a condition for the specific symbol. This could be done, for example, in `rspamd.local.lua`:

~~~lua
rspamd_config:add_condition('SOME_SYMBOL', function(task) return false end)
~~~

You can add more complex conditions but this one is the easiest in terms of rules management and upgrades.

Additionally you can dynamically selectively enable/disable symbols with [settings module](https://rspamd.com/doc/configuration/settings.html).

### Can I scan outgoing mail with Rspamd

Yes, Rspamd should be safe for outbound scanning by default, [see here for detail](https://rspamd.com/doc/tutorials/scanning_outbound.html).

## Administration questions

### How to read Rspamd logs
Rspamd logs are augmented, meaning that each log line normally includes a `tag` which can help to figure out log lines that are related to, for example, a specific task:

```
# fgrep 'b120f6' /var/log/rspamd/rspamd.log

2016-03-18 15:15:01 #29588(normal) <b120f6>; task; accept_socket: accepted connection from 127.0.0.1 port 52870
2016-03-18 15:15:01 #29588(normal) <b120f6>; task; rspamd_message_parse: loaded message; id: <201603181414.u2IEEfKL062480@repo.freebsd.org>; queue-id: <D4CFE300135>
2016-03-18 15:15:01 #29588(normal) <b120f6>; task; rspamd_task_write_log: id: <201603181414.u2IEEfKL062480@repo.freebsd.org>, qid: <D4CFE300135>, ip: 2001:1900:2254:206a::19:2, from: <owner-ports-committers@freebsd.org>, (default: F (no action): [-2.11/15.00] [MIME_GOOD,R_SPF_ALLOW,RCVD_IN_DNSWL_HI,MAILLIST,BAYES_HAM,FANN_SCORE,FORGED_RECIPIENTS_MAILLIST,FORGED_SENDER_MAILLIST]), len: 6849, time: 538.803ms real, 26.851ms virtual, dns req: 22
```

### Can I customize log output for logger
Yes, there is `log_format` option in `logging.inc`. Here is a useful configuration snippet that allows you to add more information in comparison to the default Rspamd logger output:

```ucl
log_format =<<EOD
id: <$mid>, $if_qid{ qid: <$>,} ip: [$ip], $if_user{ user: $,} smtp_from: <$smtp_from>, mime_from: <$mime_from>, smtp_rcpts: <$smtp_rcpts>, mime_rcpts: <$mime_rcpts>,
(default: $is_spam ($action): [$scores] [$symbols_scores]),
len: $len, time: $time_real real,
$time_virtual virtual, dns req: $dns_req, url domains:
$lua{
    return function(task)
      local fun = require "fun"
      local domains = {}
      local unique = fun.filter(function(dom)
        if not domains[dom] then
          domains[dom] = 1
          return true
        end
        return false
      end, fun.map(function(url) return url:get_host() end, task:get_urls()))
      local s = table.concat(fun.totable(unique), ',')
      return s
    end}
EOD
```

As you can see, you can use both embedded log variables and Lua code to customize log output. More information is available in the [logger documentation](https://rspamd.com/doc/configuration/logging.html)

### Which backend should I use for statistics

Currently, I recommend using `redis` for the statistics back end. You can convert existing statistics in sqlite by using `rspamadm statconvert` routine:

```
rspamadm statconvert -d bayes.spam.sqlite -h 127.0.0.1:6379  -s BAYES_SPAM
```

The only limitation of the redis plugin is that it doesn't support per language statistics. This feature, however, is not needed in the majority of cases. Per user statistics in redis works in a different way than in sqlite. Please read the [corresponding documentation](https://rspamd.com/doc/configuration/statistic.html) for further details.


### What Redis keys are used by Rspamd

The statistics module uses <SYMBOL><username> as keys. Statistical tokens are recorded within a hash table with the corresponding name. The `ratelimit` module uses a key for each value stored in Redis: <https://rspamd.com/doc/modules/ratelimit.html>
The DMARC module also uses multiple keys to store cumulative reports: a separate key for each domain.

It is recommended to set a limit for dynamic Rspamd data stored in Redis ratelimits, ip reputation, and DMARC reports. You could use a separate Redis instance for statistical tokens and set different limits or use separate databases (by specifying `dbname` when setting up the redis backend).

## Plugin questions

### How to whitelist messages
You have multiple options here. First of all, if you need to define a whitelist based on `SPF`, `DKIM` or `DMARC` policies, then you should look at the [whitelist module](https://rspamd.com/doc/modules/whitelist.html). Otherwise, there is a [multimap module](https://rspamd.com/doc/modules/multimap.html) that implements different types of checks to add symbols according to list matches or to set pre-actions which allow you to reject or permit certain messages. For example, to blacklist all files from the following list in attachments:

```
exe
arj
scr
lnk
```

you could define the following multimap rule in `local.d/multimap.conf`:

```ucl
filename_blacklist {
  type = "filename";
  filter = "extension";
  map = "/${LOCAL_CONFDIR}/filename.map";
  symbol = "FILENAME_BLACKLISTED";
  action = "reject";
}
```

Another option is to disable spam filtering for some senders or recipients based on [user settings](https://rspamd.com/doc/configuration/settings.html). You can specify `want_spam = yes` and Rspamd will skip messages that satisfy a particular rule's conditions.

### What are filters, pre-filters and post-filters
Rspamd executes different types of filters depending on the time of execution.

- `pre-filters` are executed before everything else and they can set a `pre-result` that ultimately classifies a message. Filters and post-filters are not executed in this case.
- `filters` are generic Rspamd rules.
- `post-filters` are guaranteed to be executed after all filters are finished and allow the execution of actions that depends on the results of scan

The overall execution order in Rspamd is the following:

1. pre-filters
2. filters
3. classifiers
4. composite symbols
5. post-filters
6. autolearn rules

### What is the meaning of the `URIBL_BLOCKED` symbol

This symbol means that you have exceeded the amount of DNS queries allowed for non-commercial usage by SURBL services. If you use some a public DNS server, e.g. goolgle public DNS, then try switching to your local DNS resolver (or set one up, for example, [unbound](https://www.unbound.net/)). Otherwise, you should consider buying a [commercial subscription](http://www.surbl.org/df) or you won't be able to use the service. The `URIBL_BLOCKED` symbol has a weight of 0 and is used just to inform you about this problem.

### What is faster between custom Lua rules and regular expressions

Switching from C to Lua might be expensive. Hence, you should use regular expressions for simple checks where possible. If Rspamd is compiled with [Hyperscan](https://01.org/hyperscan) the cost of adding another regular expression is usually very cheap. In this case, you should avoid constructions that are not supported by Hyperscan: backtracking, lookbehind and some [others](http://01org.github.io/hyperscan/dev-reference/compilation.html#unsupported-constructs). On the other hand, Lua provides some unique functions that are not available by using of regular expressions. In this case, you should use Lua.

## WebUI questions

### What are `enable_password` and `password` for the WebUI

Rspamd can limit the functions available through the WebUI in three ways:

1. Allow read-only commands when `password` is specified
2. Allow all commands when `enable_password` is specified
3. Allow all commands when client IP address matches the `secure_ip` list in the controller configuration

When `password` is specified but `enable_password` is missing then `password` is used for **both** read and write commands.

### How to store passwords securely

Rspamd can encrypt passwords and store them using [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2). To use this feature you can use the `rspamadm pw` command as follows:

```
rspamadm pw
Enter passphrase:
$1$jhicbyeuiktgikkks7in6mecr5bycmok$boniuegw5zfc77pfbqf14bjdxmzd3yajnngwdekzwhjk1daqjixb
```

Then you can use the resulting string (in the format `$<algorithm_id>$<salt>$<encrypted_data>`) as `password` or `enable_password`. Please note that this command will generate **different** encrypted strings even for the same passwords. That is the intended behaviour.

### How to use the WebUI behind a proxy server

Here is an example for nginx:

```nginx
location /rspamd/ {
  proxy_pass       http://localhost:11334/;

  proxy_set_header Host      $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For "";
}
```

Corresponding Apache configuration:

```xml
<Location /rspamd>
	Order allow,deny
	Allow from all
</Location>
RewriteRule ^/rspamd$ /rspamd/ [R,L]
RewriteRule ^/rspamd/(.*) http://localhost:11334/$1 [P,L]
```

When a connection comes from an IP listed in `secure_ip` or from a unix socket then Rspamd checks for two headers: `X-Forwarded-For` and, if that is not found- `X-Real-IP`. If one of those headers is found then Rspamd treats a connection as if it comes from the IP specified in that header. For example, `X-Real-IP: 8.8.8.8` will trigger checks against `secure_ip` for `8.8.8.8`.

### Where does the WebUI store settings

The WebUI sends `AJAX` requests for Rspamd and Rspamd can store data in a `dynamic_conf` file. By default, it is defined in `options.inc` as following:

```
dynamic_conf = "$DBDIR/rspamd_dynamic";
```

Rspamd loads symbols and actions settings from this file with priority 5 which allows you to redefine those settings in an override configuration.

### Why can't I edit some maps with the WebUI

The map file might have insufficient permissions, or not exist. The WebUI also ignores all `HTTP` maps. Editing of signed maps is not yet supported.

## Lua questions

### What is the difference between plugins and rules

Rules are intended to do simple checks and return either `true` when rule matches or `false` when rule does not match. Rules normally cannot execute any asynchronous requests or insert multiple symbols. In theory, you can do this but registering plugins by `rspamd_config:register_symbol` functions is the recommended way to perform such a task. Plugins are expected to insert results by themselves using the `task:insert_result` method.

### What is table form of a function call

The difference between table and sequential forms is simple:

```lua
func(a, b, c, d) -- sequential form
func({
  param1 = a,
  param2 = b,
  param3 = c,
  param4 = d
}) -- table form
```

Historically, all Lua methods used the sequential call type. This has changed somewhat, however, and has the following advantages:

- you don't need to remember the exact **order** of arguments
- you can see not only a value but a `name = value` pair which helps in debugging
- it is easier to **extend** methods with new features and to keep backward compatibility
- it is much easier to allow **optional** arguments

However, there is a drawback: table calls are slightly more expensive in terms of computational resources. The difference is negligible in the majority of cases so Rspamd now supports the table form for most functions which accept more than two or three arguments. You can check in the [documentation](https://rspamd.com/doc/lua/) which forms are allowed for a particular function.

### How to use rspamd modules

Use a `require` statement:

```lua
local rspamd_logger = require 'rspamd_logger'
local rspamd_regexp = require 'rspamd_regexp'
```

Rspamd also ships some additional lua modules which you can use in your rules:

- [Lua functional](https://github.com/rtsisyk/luafun)
- [Lua LPEG](http://www.inf.puc-rio.br/~roberto/lpeg/)

### How to write to Rspamd log
[Rspamd logger](https://rspamd.com/doc/lua/logger.html) provides many convenient methods to log data from lua rules and plugins. You should consider using one of the modern methods (with `x` suffix) that allow use of `%s` and `%1` .. `%N` notation. The `%s` format is used to print the **next** argument, and `%<number>` is used to process the particular argument (starting from `1`):

```lua
local rspamd_logger = require 'rspamd_logger'

rspamd_logger.infox("%s %1 %2 %s", "abc", 1, {true, 1})
-- This will show abc abc 1 [[1] = true, [2] = 1]
```

It is also possible to use other objects, such as Rspamd task or Rspamd config to augment logger output with a task or config logging tag.

Moreover, there is an `rspamd_logger.slog` function which allows replacement of the Lua standard function `string.format` when you need to print complex objects, such as tables.

### Should I use `local` for my variables

Yes: always use `local` variables unless it is unavoidable. Too many global variables can cause significant performance degradation for Lua scripts.

### How can I create regexps in Lua

Regexp objects are special in case of Rspamd. Unlike other objects, they do not have garbage collection method and should be explicitly destroyed. For example, if you have this code:

~~~lua
rspamd_config.RULE = function(task)
  local re = rspamd_regexp.create('/re/') -- Memory leak here!
  ...
end
~~~

Then `re` object will not be destroyed and you will have a memory leak. To resolve this situation, you should always use the global regexps cache which exists during Rspamd process lifetime:

~~~lua
rspamd_config.RULE = function(task)
  local re = rspamd_regexp.create_cached('/re/') -- Regexp will be reused from the cache if possible
  ...
end
~~~

The only situation when you might have a problem with this approach is when you need to create regular expressions dependant on some external data:

~~~lua
local function blah(task)
  -- Return something that depends on task properties
end

rspamd_config.RULE = function(task)
  local re = rspamd_regexp.create_cached(blah(task)) -- Too many regexps could be created
  ...
end
~~~

If you cannot avoid this bad pattern (and it is bad since regexp creation is an expensive procedure), then you can explicitly destroy regexp object:

~~~lua
local function blah(task)
  -- Return something that depends on task properties
end

rspamd_config.RULE = function(task)
  local re = rspamd_regexp.create(blah(task)) -- This is expensive procedure!
  ...
  re:destroy() -- frees memory
end
~~~

However, you should consider using regexp maps with [multimap module]({{ site.baseurl }}/doc/modules/multimap.html) when you need something like this.

## Rmilter questions

### Can Rspamd run without Rmilter

Rspamd can be integrated with an MTA using different methods described in the [integration](integration.html) document. For Postfix and Sendmail MTA `Rmilter` is the most appropriate tool. Moreover, Rmilter adds some features to Rspamd, such as conditional greylisting and message alteration. That's why I would recommend using Rmilter with Rspamd if possible (e.g. Exim doesn't support milter interface and qmail doesn't support anything but LDA mode).

### How to set up DKIM signing in Rmilter

Please use [dkim module]({{ site.baseurl }}/doc/modules/replies.html) in Rspamd.

### Setup whitelisting of reply messages

Please use [replies module]({{ site.baseurl }}/doc/modules/replies.html) in Rspamd.

### How to distinguish inbound and outbound traffic for Rspamd instance

From version 1.8.0 onwards, Rmilter can pass a special header to Rspamd called `settings-id`. This header allows Rspamd to apply specific settings for a message. You can set custom scores for a message or disable some rules or even a group of rules when scanning. For example, if we want to disable some rules for outbound scanning we could create an entry in the [settings](https://rspamd.com/doc/configuration/settings.html) module:

```ucl
settings {
  outbound {
    priority = high;
    id = "outbound";
    apply "default" {
      actions {
        reject = 150.0;
        "add header" = 6.0;
      }
      BAYES_SPAM = 7.0;
      groups_disabled = [
        "hfilter",
        "spf",
        "rbl"
      ]
    }
  }
}
```

Then, we can apply this setting ID on the outbound MTA using the Rmilter configuration:

```ucl
spamd {
  ...
  spamd_settings_id = "outbound";
}
```

Another possibility is to apply settings based merely on the sender being authenticated or having an IP address in a particular range, refer to the [documentation](https://rspamd.com/doc/configuration/settings.html) for detail.

### How can I restore the old SPF behaviour

Previously, Rmilter could reject mail which fail SPF verification for certain domains. However, this was removed. Nevertheless, this behaviour could be reproduced using Rspamd.

One can create rules in rspamd to force rejection on whatever symbols (+ other conditions) they want (DMARC module, among others has built-in support for such; [multimap](https://rspamd.com/doc/modules/multimap.html) being the most generally useful)

For example, add to `/etc/rspamd/rspamd.local.lua`:

~~~lua
local myfunc = function(task)
  if task:has_symbol('R_SPF_REJECT') then
    task:set_pre_result('reject', 'I rejected it')
  end
end
local id = rspamd_config:register_symbol('MY_REJECT', 1.0, myfunc)
rspamd_config:register_dependency(id, 'R_SPF_REJECT')
~~~

It is also possible to use rspamd to test SPF without message data but Rmilter does not currently support that.
