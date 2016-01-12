# Migrating from Spamassassin to Rspamd

This guide provides information for those who wants to migrate their existing system from [spamassassin](https://spamassassin.apache.org) to rspamd. Here you will find information about major differences between these two spam filtering engines and how to deal with the transition process.

## Why migrate to Rspamd

The first question you need to ask yourself is 'what is **wrong** with my spamassassin installation?' To my sense and according to many users' reports, rspamd runs **significantly faster** than spamassassin providing almost the same quality of filtering. However, if you don't care about performance and resources consumption of your spam filtering engine you might still find rspamd useful because it has a simple but yet powerful web management system (WebUI).

On the contrary, if you have a lot of custom rules, or if you use Pyzor/Razor/DCC, or you have some commercial 3rd party products that are SpamAssassin only then there are no clear reasons of migrating indeed.

In brief, Rspamd is for **speed**!

## What about dspam/spamoracle...?

You could also move from these projects to Rspamd. However, you should bear in mind that Rspamd and SA are multi-factor spam filtering systems that uses 3 main approaches to filter Spam messages:

* Content filtering - static rules that are designed to find some known `bad patterns` in messages (usually regexp or other custom rules)
* Dynamic lists - DNS or reputation lists that are used to filter known bad content, such as abused IP addresses or URL domains
* Statistical filters - are learned dynamically to distinguish spam and ham messages

`dspam`, `spamoracle` and many others usually implement the third approach providing merely statistical filtering. This method is quite powerful but it might cause many false-positives and is not very well suitable for more than one user. Rspamd and SA, in contrast, are designed for systems with many users. Rspamd in particular was written for a very large system with more than 40 millions of users and about 10 millions of emails per hour.

## Before you start

There are a couple of things you need to know before transition:

1. Rspamd does not support Spamassassin statistics so you'd need to **train** your filter from the scratch with spam and ham samples (or install the [pre-built statistics](https://rspamd.com/rspamd_statistics/)). Rspamd uses different statistical engine called [OSB-Bayes](http://osbf-lua.luaforge.net/papers/trec2006_osbf_lua.pdf) which is intended to be more precise than SA 'naive' bayes classifier
2. Rspamd uses `Lua` for plugins and rules, so basic knowledge of this language is more than useful for playing with rspamd, however, Lua is very simple and can be learnt [very quickly](http://lua-users.org/wiki/LuaTutorial)
3. Rspamd uses `HTTP` protocol for communicating with MTA or milter, so SA native milters might fail to communicate with rspamd. There is some limited support of SpamAssassin protocol, thought some commands are not supported, in particular those which require copying of data batween scanner and milter. What's more important is that `Length`-less messages are not supported by Rspamd as they completely break HTTP semantics, so it won't be supported ever. For achieving the same functionality, a dedicated scanner could use, e.g. HTTP `chunked` encoding.
4. Rspamd is **NOT** intended to work with blocking libraries or services, hence, something like `mysql` or `postgresql` won't likely be supported as well
5. Rspamd is developping quickly, therefore you should be aware that there might be still some incompatible changes between major versions - they are usually listed in the [migration](../migration.md) section of the site.

## The first steps in Rspamd

To install rspamd, I'd recommend using of the [official packages](https://rspamd.com/downloads.html) that are available for many popular platforms. If you'd like to have more features then you should consider `experimental` branch of packages, whilst if you'd like to have more stability then you could select the `stable` branch. However, normally even `experimental` branch is stable enough for the production usage, and the bugs are fixed more quickly in the `experimental` branch.

## General spamassassin rules

For those who has a lot of custom rules, there is good news: rspamd supports a certain set of SpamAssassin rules via special [plugin](../modules/spamassassin.md) that allows **direct** loading of SA rules into rspamd. You just need to specify all your configuration files in the plugin configuration:

~~~nginx
spamassassin {
	sa_main = "/etc/spamassassin/conf.d/*";
	sa_local = "/etc/spamassassin/local.cf";
}
~~~

On the other hand, if you don't have many custom rules and use primarily the default ruleset then you shouldn't use this plugin: many rules of SA are already implemented in rspamd natively so you won't get any benefit from including such rules from SA.

## Integration

If you have your SA up and running it is usually possible to switch the system to rspamd using the existing tools.
However, please check the [integration document](https://rspamd.com/doc/integration.html) for furhter details.

## Statistics

Rspamd statistics is not compatible with SA as it uses more advanced statistics algorithms described in the following [article](http://osbf-lua.luaforge.net/papers/trec2006_osbf_lua.pdf). Statistics setup might be tricky, therefore, there are a couple of examples in [the statistics description](../configuration/statistics.md). However, please bear in mind that you need to **relearn** your statistics with messages. This can be done, for example, by using `rspamc` command assuming that you have your messages as a separate files (e.g. `Maildir` format) placed in directories `spam` and `ham`:

	rspamc learn_spam spam/
	rspamd learn_ham ham/

You need rspamd up and running for using of this commands.

### Learning using mail interface

You can also setup rspamc to learn via passing messages to a certain email address. I'd recommend to use `/etc/aliases` for these purposes and `mail-redirect` command (e.g. provided by [Mail Redirect addon](https://addons.mozilla.org/en-GB/thunderbird/addon/mailredirect/) for `thunderbird` MUA). The desired aliases could be the following:

	learn-spam123: "| rspamc learn_spam"
	learn-ham123: "| rspamc learn_ham"

You'd need some less predictable aliases to avoid sending messages to such addresses by some adversary or just by a mistake to prevent statistics pollution.