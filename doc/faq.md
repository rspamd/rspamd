---
layout: doc_faq
title: Rspamd frequently asked questions
---

# Frequently asked questions

This document includes some questions and practical examples that are frequently asked by rspamd users.

## General questions

### Where get help about rspamd

The most convenient place for asking questions about rspamd is IRC channel *#rspamd* in <http://freenode.net>. But you can also check the [support page](https://rspamd.com/support.html)

### How to figure out why rspamd process crashed

Like other programs written in `C` language, the best way to debug these problems is to obtain `core` dump. Unfortunately, there is no universal solution suitable for all platforms, however, for FreeBSD and Linux you could do the following.

First of all, you'd need to create a special directory for core files that will be allowed for writing for all users in the system:

    mkdir /coreland
    chmod 1777 /coreland

For FreeBSD you can have either one core for all processes by setting:

    sysctl kern.corefile=/coreland/%N.core

or a separated core for each crash (that includes PID of process):

    sysctl kern.corefile=/coreland/%N-%p.core

For Linux this setting is slightly different:

    sysctl kern.corefile=/coreland/%e.core

or

    sysctl kern.corefile=/coreland/%e-%p.core

By default, you also need to explicitly permit dumping of core files by setting the appropriate resource limit. This could be done by adding the following line to your rspamd init script (`/etc/init.d/rspamd` for Linux `/usr/local/etc/rc.d/rspamd` for FreeBSD):

    ulimit -c unlimited

You should add this line just after the heading comment.

### But now I have too many core files, how to limit their amount

Rspamd can stop dumping cores upon reaching specific limit. To enable this functionality you can add the following lines to the `etc/rspamd/local.d/options.inc`:

~~~nginx
cores_dir = "/coreland/";
max_cores_size = 1G;
~~~

That will limit the joint amount of files in `/coreland/` folder to 1 gigabyte. After reaching this limit, rspamd will stop dumping core files. Rspamd cannot distinguish its own core files from other core files in a system. That is an inevitable limitation.

### What can I do with a core files

In the most cases, it is enough to open core file with `gdb`  or other debugger, such as `lldb`:

    gdb `which rspamd` -c /coreland/rspamd.core
    lldb `which rspamd` -c /coreland/rspamd.core

If a core file has been opened without errors then you can type `bt full` in debugger command line to get the full stack trace that caused this particular error.

### Why can I have different results for the same message

If your message is gains `reject` score, rspamd stops further checks to save some resources. However, some checks, such as network checks could still occur as they might be started before reaching this threshold for this message. Therefore, sometimes you might see different (but all more or equal to `reject` threshold) results for a same message. To avoid this behaviour you could set HTTP header

    Pass: all

when making request to rspamd (which is equal to `-p` flag for `rspamc` client).

Another possible reason of different results is too low DNS timeouts or too low task timeout so asynchronous rules can't get results before killed by a timeout. To get help about the relevant options you can type the following commands:

    rspamadm confighelp options.DNS
    rspamadm confighelp options.dns_max_requests
    rspamadm confighelp workers.normal.task_timeout

and more general:
    rspamadm confighelp -k timeout

### What is the difference between `rspamc` and `rspamadm`

Rspamadm is administration tool that works with **local** rspamd daemon via unix socket and performs some management tasks. You could get help for this tool and all subtools by typing:

    rspamadm help
    rspamadm help <command>

Rspamc is a client for rspamd remote daemon. It can talk with rspamd scanner process or rspamd controller process using HTTP (with optional encryption) protocol, get and fine-print the results. It can do such tasks as scanning, learning and getting statistics:

    rspamc message.eml # Scan a message
    rspamc learn_spam message.eml # Learn message
    rspamc -f 1 -w 10 fuzzy_add message.eml # Add message to fuzzy storage

## Configuration questions

### What are rspamd actions

Unlike SpamAssassin, rspamd **suggests** the desired action for a specific message scanned:

- `reject`: ultimately reject message
- `rewrite subject`: set spam subject
- `add header`: add spam header
- `greylist`: delay message for a while
- `no action`: pass message

Rspamd itself **does not** alter a message, that is a task for MTA or any shim agent (e.g. [rmilter](https://rspamd.com/rmilter/)).
All actions but `reject` and `no action` could be treated as `potential spam` and greylisted or moved to a `Junk` folder for end-user.

### What are rspamd metrics

Rspamd metrics is the concept of splitting results into different combinations. However, this concept was never used and so far there is only `default` metric that is supported by all clients I know. That's why you should consider another mechanisms to achieve this goal, for example, [user settings](https://rspamd.com/doc/configuration/settings.html).

### What are local and override config files

Historically, rspamd provided configuration files that were desired for editing by hands. However, with the project development it has come clear that this idea does not fit very well: rspamd configuration influences the overall filtering quality, performance and other important metrics. Unfortunately, with the hand edited configuration files it is very hard to maintain these metrics up-to-date. Hence, I have decided to add two possibilities:

1. Override configurations
2. Local configurations

Override configuration (`etc/rspamd.conf.override`) is used to ultimately redefine the default values in rspamd. In this file, you redefine the **whole sections** of the default configuration. For example, if you have some module `example` defined in the default configuration as following:

~~~nginx
example {
  option1 = "value";
  option2 = true;
}
~~~

and then you decided to override `option2` and tried to add the following content to the `etc/rspamd.conf.override` file:

~~~nginx
example {
  option2 = false;
}
~~~

However, this might work unexpectedly: overrided config would have `example` section with a single key `option2` whilst `option1` will be missed. The global local file, namely, `rspamd.conf.local` has the same limitation: you can add your own configuration there but you should **NOT** redefine anything from the default configuration there or that things will be just ignored. The only exception from this rule is *metric* section. So you could use something like:

~~~nginx
metric "default" {
  symbol "MY_SYMBOL" {
    score = 10.0;
    description = "my rule";
  }
}
~~~

and add this to the `rspamd.conf.local` (but not override).

### What are local.d and override.d then

From `rspamd 1.2`, the default configuration also provides 2 more ways to extend or redefine each configuration file shipped with rspamd. Within section definition, it includes 2 files with different priorities:

* `etc/rspamd/local.d/<conf_file>` - included with priority `1` that allows to redefine and extend the default rules but `dynamic updates` or things redefined via `webui` will have higher priority and can redefine the values included
* `etc/rspamd/override.d/<conf_file>` - included with priority `10` that allows to redefine all other things that could change configuration in rspamd

Another important difference from the global override and local rules is that these files are included within section. Here is an example of utilizing of local.d for `modules.d/example.conf` configuration file:

~~~nginx
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
~~~

in `local.d/example.conf`:

~~~nginx
example {
  option2 = false;
  option3 = 1.0;
}
~~~

in  `override.d/example.conf`:

~~~nginx
example {
  option3 = 2.0;
  option4 = ["something"];
}
~~~

and the target configuration (that you could see using `rspamadm configdump example`):

~~~nginx
example {
  option1 = "value"; # From default settings
  option2 = false; # From local.d
  option3 = 2.0; # Local is overrided by override
  option4 = ["something"]; # From override.d
}
~~~

This looks complicated but it allows smoother updates and simplifies automatic management. If you unsure about your configuration, then take a look at `rspamadm configdump` command that displays the target configuration with many options available and `rspamadm confighelp` that shows help for many of rspamd options.

### What are maps

Maps are files that contain lists of keys or key-value pairs that could be dynamically reloaded by rspamd when changed. The important difference to configuration elements is that maps reloading is done on flight without expensive restart procedure. Another important thing about maps is that rspamd can monitor both file and HTTP maps for changes (modification time for files and HTTP `If-Modified-Since` header for HTTP maps). Rspamd supports `HTTP` and `file` maps so far.

### What can be in the maps

Maps can have the following objects:

* spaces and one line comments started by `#` symbols
* keys
* optional values separated by space character
* keys with spaces enclosed in double quotes
* keys with slashes (regular expressions) enclosed in slashes
* `IP` addresses with optional mask

Here are some examples:

    key1 # Single key
    # Comment ignored

    # Empty line ignored
    key2 1 # Key and value
    "key3 with space"
    "key with \" escaped" value with spaces

Regexp maps:

    /regexp/i
    /regexp/is some other value

IP maps:

    192.168.0.1 # Mask is /32
    [::1] # Mask is /128
    [::1]/64
    192.168.0.1/19

### How to sign maps

From rspamd 1.2 each map can have digital signature using `EdDSA` algorithm. To sign a map you can use `rspamadm signtool` and to generate signing keypair - `rspamadm kaypair -s -u`:

~~~nginx
keypair {
   pubkey = "zo4sejrs9e5idqjp8rn6r3ow3x38o8hi5pyngnz6ktdzgmamy48y";
   privkey = "pwq38sby3yi68xyeeuup788z6suqk3fugrbrxieri637bypqejnqbipt1ec9tsm8h14qerhj1bju91xyxamz5yrcrq7in8qpsozywxy";
   id = "bs4zx9tcf1cs5ed5mt4ox8za54984frudpzzny3jwdp8mkt3feh7nz795erfhij16b66piupje4wooa5dmpdzxeh5mi68u688ixu3yd";
   encoding = "base32";
   algorithm = "curve25519";
   type = "sign";
}
~~~

Then you can use `signtool` to edit map's file:

    rspamadm signtool -e --editor=vim -k <keypair_file> <map_file>

To enforce signing policies you should add `sign+` string to your map definition:

    map = "sign+http://example.com/map"

To specify trusted key you could either put **public** key from the keypair to `local.d/options.inc` file as following:

    trusted_keys = ["<public key string>"];

or add it as `key` definition to the map string:

    map = "sign+key=<map_string>http://example.com/map"

## Administration questions

## Plugins questions

### How to whitelist messages

You have multiple options here. First of all, if you need to define whitelist based on `SPF`, `DKIM` or `DMARC` policies, then you should look at [whitelist module](https://rspamd.com/doc/modules/whitelist.html). Otherwise, there is [multimap module](https://rspamd.com/doc/modules/multimap.html) that implements different types of checks to add symbols according to lists match or to set pre-action allowing to inevitably reject or permit certain messages. For example, to blacklist all files from the following list in attachments:

    exe
    arj
    scr
    lnk

you could define the following multimap rule in `local.d/multimap.conf`:

~~~nginx
filename_blacklist {
  type = "filename";
  filter = "extension";
  map = "/${LOCAL_CONFDIR}/filename.map";
  symbol = "FILENAME_BLACKLISTED";
  action = "reject";
}
~~~

### What are filters, pre-filters and post-filters

Rspamd allows different types of filters depending on time of execution.

* `pre-filters` are executed before everything else and they can set so called `pre-result` that ultimately classifies message setting the desired action. Filters and post-filters are not executed in this cases
* `filters` are generic rspamd rules that are planned by rules scheduler
* `post-filters` are guaranteed to be executed after all filters are finished that allows to execute actions that depends on result of scan

The overall execution order in rspamd is the following:

1. pre-filters
2. filters
3. classifiers
4. composite symbols
5. post-filters
6. autolearn rules

Pre-filters can skip all other steps. Rules can define dependencies on other rules. It is not possible neither to define dependencies on other categories of rules but normal filters nor to define dependencies inter-categories dependencies, such as pre-filters on normal filters for example.

## WebUI questions

## LUA questions
