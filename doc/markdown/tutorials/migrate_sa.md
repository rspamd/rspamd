# Migrating from SpamAssassin to Rspamd

This guide provides information for those who wants to migrate an existing system from [SpamAssassin](https://spamassassin.apache.org) to rspamd. You will find information about major differences between the spam filtering engines and how to deal with the transition process.

## Why migrate to rspamd

rspamd runs **significantly faster** than SpamAssassin while providing approximately the same quality of filtering. However, if you don't care about the performance and resource consumption of your spam filtering engine you might still find rspamd useful because it has a simple but powerful web management system (WebUI).

On the other hand, if you have a lot of custom rules, or you use Pyzor/Razor/DCC, or you have some commercial 3rd party products that depend on SpamAssassin then you may not want to migrate.

In short: rspamd is for **speed**!

## What about dspam/spamoracle...?

You could also move from these projects to rspamd. You should bear in mind, however, that rspamd and SA are multi-factor spam filtering systems that use three main approaches to filter messages:

* Content filtering - static rules that are designed to find known bad patterns in messages (usually regexp or other custom rules)
* Dynamic lists - DNS or reputation lists that are used to filter known bad content, such as abused IP addresses or URL domains
* Statistical filters - which learn to distinguish spam and ham messages

`dspam`, `spamoracle` and others usually implement the third approach, only providing statistical filtering. This method is quite powerful but it can cause false-positives and is not very suitable for multi-user environments. rspamd and SA, in contrast, are designed for systems with many users. rspamd, in particular, was written for a very large system with more than 40 million users and about 10 million emails per hour.

## Before you start

There are a couple of things you need to know before transition:

1. rspamd does not support SpamAssassin statistics so you'd need to **train** your filter from scratch with spam and ham samples (or install the [pre-built statistics](https://rspamd.com/rspamd_statistics/)). rspamd uses a different statistical engine - called [OSB-Bayes](http://osbf-lua.luaforge.net/papers/trec2006_osbf_lua.pdf) - which is intended to be more precise than SA's 'naive' Bayes classifier
2. rspamd uses `Lua` for plugins and rules, so basic knowledge of this language is more than useful for playing with rspamd; however, Lua is very simple and can be learned [very quickly](http://lua-users.org/wiki/LuaTutorial)
3. rspamd uses the `HTTP` protocol to communicate with the MTA or milter, so SA native milters might not communicate with rspamd. There is some limited support of the SpamAssassin protocol, though some commands are not supported, in particular those which require copying of data between scanner and milter. More importantly, `Length`-less messages are not supported by rspamd as they completely break HTTP semantics and will never be supported. To achieve the same functionality, a dedicated scanner could use, e.g. HTTP `chunked` encoding.
4. rspamd is **NOT** intended to work with blocking libraries or services, hence, something like `mysql` or `postgresql` will likely not be supported
5. rspamd is developing quickly so you should be aware that there might be some incompatible changes between major versions - they are usually listed in the [migration](../migration.md) section of the site.
6. Unlike SA where there are only `spam` and `ham` results, Rspamd supports five levels of messages called `actions`:
	+ `no action` - ham message
	+ `greylist` - turn on adaptive greylisting (which is also used on higher levels)
	+ `add header` - adds Spam header (meaning soft-spam action)
	+ `rewrite subject` - rewrite subject to `*** SPAM *** original subject`
	+ `reject` - ultimately reject message

Each action can have its own score limit which could also be modified by a user's settings. rspamd assumes the following order of actions: `no action` <= `greylist` <= `add header` <= `rewrite subject` <= `reject`.

Actions are **NOT** performed by rspamd itself - they are just recommendations for the MTA agent, rmilter for example, that performs the necessary actions such as adding headers or rejecting mail.

SA `spam` is almost equal to the rspamd `add header` action in the default setup. With this action, users will be able to check messages in their `Junk` folder, which is usually a desired behaviour.

## First steps with rspamd

To install rspamd, I recommend using one of the [official packages](https://rspamd.com/downloads.html) that are available for many popular platforms. If you'd like to have more features then you can consider the `experimental` branch of packages, while if you would like to have more stability then you can select the `stable` branch. However, normally even the `experimental` branch is stable enough for production use, and bugs are fixed more quickly in the `experimental` branch.

## General SpamAssassin rules

For those who have a lot of custom rules, there is good news: rspamd supports a certain set of SpamAssassin rules via a special [plugin](../modules/spamassassin.md) that allows **direct** loading of SA rules into rspamd. You just need to specify your SA configuration files in the plugin configuration:

~~~ucl
spamassassin {
	sa_main = "/etc/spamassassin/conf.d/*";
	sa_local = "/etc/spamassassin/local.cf";
}
~~~

On the other hand, if you don't have a lot of custom rules and primarily use the default ruleset then you shouldn't use this plugin: many SA rules are already implemented natively in rspamd so you won't get any benefit from including such rules from SA.

## Integration

If you have your SA up and running it is usually possible to switch the system to rspamd using the existing tools. However, please check the [integration document](https://rspamd.com/doc/integration.html) for further details.

## Statistics

rspamd statistics are not compatible with SA as rspamd uses a more advanced statistics algorithm, described in the following [article](http://osbf-lua.luaforge.net/papers/trec2006_osbf_lua.pdf), so please bear in mind that you need to **relearn** your statistics. This can be done, for example, by using the `rspamc` command: assuming that you have your messages in separate files (e.g. `maildir` format), placed in directories `spam` and `ham`:

	rspamc learn_spam spam/
	rspamd learn_ham ham/

(You will need rspamd up and running to use these commands.)

### Learning using mail interface

You can also setup rspamc to learn via passing messages to a certain email address. I'd recommend using `/etc/aliases` for this purpose and a `mail-redirect` command (e.g. provided by [Mail Redirect addon](https://addons.mozilla.org/en-GB/thunderbird/addon/mailredirect/) for `thunderbird` MUA). The desired aliases could be the following:

	learn-spam123: "| rspamc learn_spam"
	learn-ham123: "| rspamc learn_ham"

(You would need to use less predictable aliases to avoid the sending of messages to such addresses by an adversary, or just by mistake, to prevent statistics pollution.)
