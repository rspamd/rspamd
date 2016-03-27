---
layout: doc_faq
title: Rspamd frequently asked questions
---

# Frequently asked questions
This document includes some questions and practical examples that are frequently asked by rspamd users.

## General questions
### Where get help about rspamd
The most convenient place for asking questions about rspamd is IRC channel _#rspamd_ in [http://freenode.net](http://freenode.net). For more information you can also check the [support page](https://rspamd.com/support.html)

### How to figure out why rspamd process crashed
Like other programs written in `C` language, the best way to debug these problems is to obtain `core` dump. Unfortunately, there is no universal solution suitable for all platforms, however, for FreeBSD and Linux you could do the following.

First of all, you'd need to create a special directory for core files that will be allowed for writing for all users in the system:

```
mkdir /coreland
chmod 1777 /coreland
```

For FreeBSD you can have either one core for all processes by setting:

```
sysctl kern.corefile=/coreland/%N.core
```

or a separated core for each crash (that includes PID of process):

```
sysctl kern.corefile=/coreland/%N-%p.core
```

For Linux this setting is slightly different:

```
sysctl kern.corefile=/coreland/%e.core
```

or

```
sysctl kern.corefile=/coreland/%e-%p.core
```

By default, you also need to explicitly permit dumping of core files by setting the appropriate resource limit. This could be done by adding the following line to your rspamd init script (`/etc/init.d/rspamd` for Linux `/usr/local/etc/rc.d/rspamd` for FreeBSD):

```
ulimit -c unlimited
```

You should add this line just after the heading comment.

### Well, now I have too many core files, how to limit their amount
Rspamd can stop dumping cores upon reaching specific limit. To enable this functionality you can add the following lines to the `etc/rspamd/local.d/options.inc`:

```ucl
cores_dir = "/coreland/";
max_cores_size = 1G;
```

That will limit the joint amount of files in `/coreland/` folder to 1 gigabyte. After reaching this limit, rspamd will stop dumping core files. Rspamd cannot distinguish its own core files from other core files in a system. That is an inevitable limitation.

### What can I do with a core files
In the most cases, it is enough to open core file with `gdb`  or other debugger, such as `lldb`:

```
gdb `which rspamd` -c /coreland/rspamd.core
lldb `which rspamd` -c /coreland/rspamd.core
```

If a core file has been opened without errors then you can type `bt full` in debugger command line to get the full stack trace that caused this particular error.

### Why can I have different results for the same message
If your message is gains `reject` score, rspamd stops further checks to save some resources. However, some checks, such as network checks could still occur as they might be started before reaching this threshold for this message. Therefore, sometimes you might see different (but all more or equal to `reject` threshold) results for a same message. To avoid this behaviour you could set HTTP header

```
Pass: all
```

when making request to rspamd (which is equal to `-p` flag for `rspamc` client).

Another possible reason of different results is too low DNS timeouts or too low task timeout so asynchronous rules can't get results before killed by a timeout. To get help about the relevant options you can type the following commands:

```
rspamadm confighelp options.DNS
rspamadm confighelp options.dns_max_requests
rspamadm confighelp workers.normal.task_timeout
```

and more general:

```
rspamadm confighelp -k timeout
```

### What is the difference between `rspamc` and `rspamadm`
Rspamadm is administration tool that works with **local** rspamd daemon via unix socket and performs some management tasks. You could get help for this tool and all subtools by typing:

```
rspamadm help
rspamadm help <command>
```

Rspamc is a client for rspamd remote daemon. It can talk with rspamd scanner process or rspamd controller process using HTTP (with optional encryption) protocol, get and fine-print the results. It can do such tasks as scanning, learning and getting statistics:

```
rspamc message.eml # Scan a message
rspamc learn_spam message.eml # Learn message
rspamc -f 1 -w 10 fuzzy_add message.eml # Add message to fuzzy storage
```

### How rspamd support different characters sets

By default, rspamd converts all messages to `UTF-8`. This includes text parts (both `text/plain` and `text/html`), headers and MIME elements (boundaries, filenames). If there is no information of how to convert something to `UTF-8`, for example when there is no `charset` attribute in the `Content-Type` or if there are some broken `UTF-8` characters then rspamd treats this text as raw for safety considerations. The difference between raw and `UTF-8` texts is that for `UTF-8` texts it is possible to use unicode regular expressions by specifying `/U` flag. For raw texts, rspamd uses raw complementary expression which could lack some features.

It is always safe to assume that everything will be in `utf-8`, even in the case of raw messages - you would just miss some particular features. There is also module called [chartable](https://rspamd.com/doc/modules/chartable.html) that checks for different unicode (or `ASCII` - non `ASCII` characters in raw mode) symbols and trying to guess if there is some obscuring attempt to mix characters sets.

### Can I relearn messages for fuzzy storage or for statistics

In case if you need to move some hash from one list (e.g. blacklist) to another one (e.g. whitelist), you need to call `rspamc fuzzy_del` command for the first list (lists are identified by number) followed by `rspamc fuzzy_add` command:

```
rspamc -f 1 fuzzy_del message.eml
rspamc -f 2 -w <weight> fuzzy_add message.eml
```

If you need just to increase the score, then just call `fuzzy_add` with the score change. It is not possible to decrease score however.

Statistics is a bit different. Rspamd keeps hashes of tokens learned in a special storage called `learn_cache`. If rspamd finds that this particular tokens combination has been already learned it performs the following:

* if the class of tokens was the same (e.g. spam and spam) then rspamd just refuses to learn these tokens one more time
* otherwise, rspamd performs so called `relearning`:
    + scores in the current class are decreased for this tokens set;
    + scores in the opposite class are increased for this tokens set;
    + the class of tokens in the learn cache is updated accordingly.

All these actions are performed automatically if `learn_cache` is enabled. It is highly recommended to use this logic since multiple learnings are quite bad for statistical module.


### Why some symbols have different scores for different messages

Rspamd support so called `dynamic` symbols. The closest analogue in SA are multiple symbols that checks for some certain value (e.g. bayes probability). In rspamd it works in a more smoother way: the metric score is multiplied by some value (that is usually in range `[0..1]`) and added to the scan result. For example, bayes classifier adds score based on probability:

* if probability is close to `50%` then score is very close to 0;
* if probability goes higher `[50% .. 75%]` then score slowly grows;
* when the probability is closer to `90%` the symbol's score is close to 0.95 and on `100%` it is exactly 1.0;
* this logic is reversed for HAM probability (from `50%` to `0%` spam probability)

This allows to provide better fit between some rule's results and the desired score. Indeed, we should intuitively add higher scores for high probabilities and fairly low scores for lower probabilities.

Many rspamd rules, such as `PHISHING` or fuzzy checks use this dynamic logic of scoring.

### Can I check message on rspamd without rspamc

Yes: `curl --data-binary @- http://localhost:11333 < file.eml`.

## Configuration questions

### What are rspamd actions

Unlike SpamAssassin, rspamd **suggests** the desired action for a specific message scanned:

- `reject`: ultimately reject message
- `rewrite subject`: set spam subject
- `add header`: add spam header
- `greylist`: delay message for a while
- `no action`: pass message

Rspamd itself **does not** alter a message, that is a task for MTA or any shim agent (e.g. [rmilter](https://rspamd.com/rmilter/)). All actions but `reject` and `no action` could be treated as `potential spam` and greylisted or moved to a `Junk` folder for end-user.

### What are rspamd metrics
Rspamd metrics is the concept of splitting results into different combinations. However, this concept was never used and so far there is only `default` metric that is supported by all clients I know. That's why you should consider another mechanisms to achieve this goal, for example, [user settings](https://rspamd.com/doc/configuration/settings.html).

### What are local and override config files
Historically, rspamd provided configuration files that were desired for editing by hands. However, with the project development it has come clear that this idea does not fit very well: rspamd configuration influences the overall filtering quality, performance and other important metrics. Unfortunately, with the hand edited configuration files it is very hard to maintain these metrics up-to-date. Hence, I have decided to add two possibilities:

1. Override configurations
2. Local configurations

Override configuration (`etc/rspamd.conf.override`) is used to ultimately redefine the default values in rspamd. In this file, you redefine the **whole sections** of the default configuration. For example, if you have some module `example` defined in the default configuration as following:

```ucl
example {
  option1 = "value";
  option2 = true;
}
```

and then you decided to override `option2` and tried to add the following content to the `etc/rspamd.conf.override` file:

```ucl
example {
  option2 = false;
}
```

However, this might work unexpectedly: overrided config would have `example` section with a single key `option2` whilst `option1` will be missed. The global local file, namely, `rspamd.conf.local` has the same limitation: you can add your own configuration there but you should **NOT** redefine anything from the default configuration there or that things will be just ignored. The only exception from this rule is _metric_ section. So you could use something like:

```ucl
metric "default" {
  symbol "MY_SYMBOL" {
    score = 10.0;
    description = "my rule";
  }
}
```

and add this to the `rspamd.conf.local` (but not override).

### What are local.d and override.d then
From `rspamd 1.2`, the default configuration also provides 2 more ways to extend or redefine each configuration file shipped with rspamd. Within section definition, it includes 2 files with different priorities:

- `etc/rspamd/local.d/<conf_file>` - included with priority `1` that allows to redefine and extend the default rules but `dynamic updates` or things redefined via `webui` will have higher priority and can redefine the values included
- `etc/rspamd/override.d/<conf_file>` - included with priority `10` that allows to redefine all other things that could change configuration in rspamd

Another important difference from the global override and local rules is that these files are included within section. Here is an example of utilizing of local.d for `modules.d/example.conf` configuration file:

```ucl
example {
  # Webui include
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

in  `override.d/example.conf`:

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

This looks complicated but it allows smoother updates and simplifies automatic management. If you unsure about your configuration, then take a look at `rspamadm configdump` command that displays the target configuration with many options available and `rspamadm confighelp` that shows help for many of rspamd options.

### What are maps
Maps are files that contain lists of keys or key-value pairs that could be dynamically reloaded by rspamd when changed. The important difference to configuration elements is that maps reloading is done on flight without expensive restart procedure. Another important thing about maps is that rspamd can monitor both file and HTTP maps for changes (modification time for files and HTTP `If-Modified-Since` header for HTTP maps). Rspamd supports `HTTP` and `file` maps so far.

### What can be in the maps

Maps can have the following objects:

- spaces and one line comments started by `#` symbols
- keys
- optional values separated by space character
- keys with spaces enclosed in double quotes
- keys with slashes (regular expressions) enclosed in slashes
- `IP` addresses with optional mask

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
From rspamd 1.2 each map can have digital signature using `EdDSA` algorithm. To sign a map you can use `rspamadm signtool` and to generate signing keypair - `rspamadm kaypair -s -u`:

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

Then you can use `signtool` to edit map's file:

```
rspamadm signtool -e --editor=vim -k <keypair_file> <map_file>
```

To enforce signing policies you should add `sign+` string to your map definition:

```
map = "sign+http://example.com/map"
```

To specify trusted key you could either put **public** key from the keypair to `local.d/options.inc` file as following:

```
trusted_keys = ["<public key string>"];
```

or add it as `key` definition to the map string:

```
map = "sign+key=<key_string>+http://example.com/map"
```

### What are one-shot rules

In rspamd, each rule can be triggered multiple times. For example, if a message has 10 URLs and 8 of them are in some URL blacklist (based on their unique tld), then rspamd would add URIBL rule 8 times for this message. Sometimes, that's not a desired behaviour - in that case just add `one_shot = true` to the symbol's definition in metric and that symbol won't be added more than one time.

### What is the use of symbol groups

Symbol groups are intended to group somehow similar rules. The most useful feature is that group names could be used in composite expressions as `gr:<group_name>` and it is possible to set joint limit of score for a specific group:

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

In this case, if `test1` and `test2` both matches their joint score won't be more than `15`.

### Why some symbols are missing in the metric configuration

It is now possible to set up rules completely from lua. That allows to set all necessary attributes without touching of configuration files. However, it is still possible to override this default scores in any configuration file. Here is an example of such a rule:

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

You can use the same approach when your own writing rules in `rspamd.local.lua`.

### How can I disable some rspamd rules safely

The best way to do it is to add so called `condition` for the specific symbol. This could be done, for example, in `rspamd.local.lua`:

~~~lua
rspamd_config:add_condition('SOME_SYMBOL', function(task) return false end)
~~~

You can add more complex conditions but this one is the easiest in terms of rules management and upgradeability.

## Administration questions

### How to read rspamd logs
Rspamd logs are augmented meaning that each log line normally includes `tag` which could help to figure out log lines that are related to, for example, a specific task:

```
# fgrep 'b120f6' /var/log/rspamd/rspamd.log

2016-03-18 15:15:01 #29588(normal) <b120f6>; task; accept_socket: accepted connection from 127.0.0.1 port 52870
2016-03-18 15:15:01 #29588(normal) <b120f6>; task; rspamd_message_parse: loaded message; id: <201603181414.u2IEEfKL062480@repo.freebsd.org>; queue-id: <D4CFE300135>
2016-03-18 15:15:01 #29588(normal) <b120f6>; task; rspamd_task_write_log: id: <201603181414.u2IEEfKL062480@repo.freebsd.org>, qid: <D4CFE300135>, ip: 2001:1900:2254:206a::19:2, from: <owner-ports-committers@freebsd.org>, (default: F (no action): [-2.11/15.00] [MIME_GOOD,R_SPF_ALLOW,RCVD_IN_DNSWL_HI,MAILLIST,BAYES_HAM,FANN_SCORE,FORGED_RECIPIENTS_MAILLIST,FORGED_SENDER_MAILLIST]), len: 6849, time: 538.803ms real, 26.851ms virtual, dns req: 22
```

### Can I customize log output for logger
Yes, there is `log_format` option in `logging.inc`. Here is a useful configuration snippet that allows to add more information comparing to the default rspamd logger output:

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

### What backend should I select for statistics

Currently, I'd recommend `redis` for statistics backend. You can convert the existing statistics in sqlite by using `rspamadm statconvert` routine:

```
rspamadm statconvert -d bayes.spam.sqlite -h 127.0.0.1:6379  -s BAYES_SPAM
```

The only limitation of redis plugin is that it doesn't support per language statistics, however, this feature is not needed in the vast majority of use cases. Per user statistic in redis works in a different way than one in sqlite. Please read the [corresponding documentation](https://rspamd.com/doc/configuration/statistic.html) for further details.


### What redis keys are used by rspamd

Statistics module uses <SYMBOL><username> as keys. Statistical tokens live within hash table with the corresponding name. `ratelimit` module uses a key for each value stored in redis: <https://rspamd.com/doc/modules/ratelimit.html>
DMARC module also uses multiple keys to store cumulative reports: a separate key for each domain.

In conclusion, it is recommended to set a limit for dynamic rspamd data stored in redis: ratelimits, ip reputation, dmarc reports. You could use a separate redis instance for for statistical tokens and set different limits (to fit all tokens) or separated database (by specifying `dbname` when setting up redis backend).  

## Plugins questions

### How to whitelist messages
You have multiple options here. First of all, if you need to define whitelist based on `SPF`, `DKIM` or `DMARC` policies, then you should look at [whitelist module](https://rspamd.com/doc/modules/whitelist.html). Otherwise, there is [multimap module](https://rspamd.com/doc/modules/multimap.html) that implements different types of checks to add symbols according to lists match or to set pre-action allowing to inevitably reject or permit certain messages. For example, to blacklist all files from the following list in attachments:

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

Another option is to disable spam filtering for some senders or recipients based on [user settings](https://rspamd.com/doc/settings.html). You might set `want_spam = yes` in settings' action and rspamd would skip messages that satisfy a particular settings rule's conditions.

### What are filters, pre-filters and post-filters
Rspamd allows different types of filters depending on time of execution.

- `pre-filters` are executed before everything else and they can set so called `pre-result` that ultimately classifies message setting the desired action. Filters and post-filters are not executed in this cases
- `filters` are generic rspamd rules that are planned by rules scheduler
- `post-filters` are guaranteed to be executed after all filters are finished that allows to execute actions that depends on result of scan

The overall execution order in rspamd is the following:

1. pre-filters
2. filters
3. classifiers
4. composite symbols
5. post-filters
6. autolearn rules

Pre-filters can skip all other steps. Rules can define dependencies on other rules. It is not possible neither to define dependencies on other categories of rules but normal filters nor to define dependencies inter-categories dependencies, such as pre-filters on normal filters for example.

### What is the meaning of `URIBL_BLOCKED` symbol

This symbol means that you have exceed the amount of DNS queries allowed for non-commercial usage by SURBL terms. If you use some public DNS server, e.g. goolgle public DNS, then try switching to your local DNS resolver (or setup one, for example, [unbound](https://www.unbound.net/)). Otherwise, you should consider buying [commercial subscription](http://www.surbl.org/df) or you won't be able to use this service. `URIBL_BLOCKED` itself has zero weight and is used just to inform you about this problem.

## WebUI questions

### What are `enable_password` and `password` for WebUI

Rspamd can limit functions available to WebUI by 3 ways:

1. Allow read-only commands when `password` is specified
2. Allow all commands when `enable_password` is specified
3. Allow all commands when IP matches `secure_ip` list in the controller configuration

When `password` is specified but `enable_password` is missing then `password` is used for **both** read and write commands.

### How to store passwords securely

Rspamd can encrypt passwords stored using [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2). To use this feature you can use `rspamadm pw` command as following:

```
rspamadm pw
Enter passphrase:
$1$jhicbyeuiktgikkks7in6mecr5bycmok$boniuegw5zfc77pfbqf14bjdxmzd3yajnngwdekzwhjk1daqjixb
```

Then you can use the resulting string (that has a format `$<algorithm_id>$<salt>$<encrypted_data>`) as `password` or `enable_password`. Please mention, that this command will generate **different** encrypted strings even for the same passwords. That is the intended behaviour.

### How to use WebUI behind proxy server

Here is an example for nginx:

```nginx
location /rspamd/ {
  proxy_pass       http://localhost:11334/;

  proxy_set_header Host      $host;
  proxy_set_header X-Real-IP $remote_addr;
}
```

When a connection comes from an IP listed in `secure_ip` or from a unix socket then rspamd checks for 2 headers: `X-Forwarded-For` and `X-Real-IP`. If any of those headers is found then rspamd treats a connection as if it comes from the IP specified in that header. For example, `X-Real-IP: 8.8.8.8` will trigger checks against `secure_ip` for `8.8.8.8`. That helps to organize `secure_ip` when connections are forwarded to rspamd.

### Where WebUI stores results

WebUI sends `AJAX` requests for rspamd and rspamd can store data in so called `dynamic_conf` file. By default, it is defined in `options.inc` as following:

```
dynamic_conf = "$DBDIR/rspamd_dynamic";
```

Rspamd loads symbols and actions settings from this file with priority 5 which allows you to redefine those settings in override configuration.

### Why cannot I edit some maps with WebUI

They might have insufficient permissions or be absent in the filesystem. Rspamd also ignores all `HTTP` maps. Signed maps are not yet supported as well.

## LUA questions

### What is the difference between plugins and rules

Rules are intended to do simple checks and return either `true` when rule matches or `false` when rule does not match. Rules normally cannot execute any asynchronous requests nor insert multiple symbols. In theory, you can do this but registering plugins by `rspamd_config:register_symbol` functions is the recommended way for such a task. Plugins are expected to insert results by themselves using `task:insert_result` method.

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

Historically, all Lua methods used the sequential call type. However, it has changed so far: many functions converted to allow table form invocation. The advantages of table form are clear:

- you don't need to remember the exact **order** of arguments;
- you can see not only a value but a `name = value` pair which helps in debugging;
- it is easier to **extend** methods with new features and to keep backward compatibility;
- it is much easier to allow **optional** arguments

However, there is a drawback: table call is slightly more expensive in terms of computational resources. The difference is negligible in the vast majority of case, so rspamd now supports table form for the most of function that accept more than two or three arguments. You can always check in the [documentation](https://rspamd.com/doc/lua/) about what forms are allowed for a particular function.

### How to use rspamd modules
The normal way is to use `require` statement:

```lua
local rspamd_logger = require 'rspamd_logger'
local rspamd_regexp = require 'rspamd_regexp'
```

Rspamd also ships some additional lua modules which you can use in your rules:

- [Lua functional](https://github.com/rtsisyk/luafun)
- [Lua LPEG](http://www.inf.puc-rio.br/~roberto/lpeg/)

### How to write to rspamd log
[Rspamd logger](https://rspamd.com/doc/lua/logger.html) provides many convenient methods to log data from lua rules and plugins. You should consider using of the modern methods (with `x` suffix) that allows to use `%s` and `%1` .. `%N` to fine print passed arguments. `%s` format is used to print the **next** argument, and `%<number>` is used to process the particular argument (starting from `1`):

```lua
local rspamd_logger = require 'rspamd_logger'

rspamd_logger.infox("%s %1 %2 %s", "abc", 1, {true, 1})
-- This will show abc abc 1 [[1] = true, [2] = 1]
```

It is also possible to use other objects, such as rspamd task or rspamd config to augment logger output with task or config logging tag.

Moreover, there is function `rspamd_logger.slog` that allows you to replace lua standard function `string.format` when you need to print complex objects, such as tables.

### Should I use `local` for my variables

The answer is yes: always use `local` variables unless it is completely inevitable. Many global variables can cause significant performance degradation for all lua scripts.
