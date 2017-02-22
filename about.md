---
layout: default
title: About Rspamd
---

## Introduction

[Rspamd]({{ site.url }}{{ site.baseurl }}) is an advanced spam filtering system supporting a variety of filtering mechanisms
including regular expressions, statistical analysis and custom services
such as URL black lists. Each message is analysed by rspamd and given a `spam score`.

According to this spam score and the user's settings rspamd recommends an action for
the MTA to apply to the message- for example to pass, reject or add a header.
Rspamd is designed to process hundreds of messages per second simultaneously.

You can watch the following [introduction video](https://www.youtube.com/watch?v=_fl9i-az_Q0) from [FOSDEM-2016](http://fosdem.org) where I describe the main features of rspamd and explain why rspamd runs so fast.

Rspamd is [packaged]({{ site.url }}{{ site.baseurl }}/downloads.html) for the major Linux distributions and is also available via [FreeBSD ports](https://freshports.org/mail/rspamd) and NetBSD [pkgsrc](https://pkgsrc.org).

## Spam filtering features

Spam filtering features implemented in Rspamd include:

* **Regular expressions filtering** - allows processing of messages, their textual parts, MIME headers and
SMTP data received by the MTA against a set of expressions including both normal regular expressions and
message processing functions. Rspamd expressions are a powerful tool for filtering messages based on
predefined rules. This feature is similar to regular expressions in spamassassin spam filter.


* **SPF module** validates a message's origin against the policy defined in the DNS record of sender's domain. You can read
about SPF policies [here](http://www.openspf.org/). A number of mail systems include SPF support, such as `gmail` or `yahoo mail`.


* **DKIM module** validates a message cryptographic signature against a public key placed in the DNS record of sender's domain. Like SPF,
this technique is widely adopted and validates that a message was sent from a specific domain.


* **DNS black lists** allows to estimate reputation of sender's IP address or network. Rspamd uses a number of DNS lists including such lists as
`SORBS` or `spamhaus`. However, rspamd doesn't trust any specific DNS list and instead uses a conjunction of estimations to
avoid mistakes and false positives. Rspamd also uses positive and grey DNS lists for checking for trusted senders.


* **URL black lists** are rather similar to DNS black lists but measure reputation of domains seen in URLs.
This technique is very useful for finding malicious domains.


* **Statistics** - rspamd uses a bayesian classifier based on five gramms of input. This means that the input is evaluated not based on individual
words, but organized into chains. This approach achieves better results than
traditionally used monogramms (or words literally speaking). It's described in detail in [this paper](http://osbf-lua.luaforge.net/papers/osbf-eddc.pdf).


* **Fuzzy hashes** - for identifying malicious mail patterns rspamd uses so-called `fuzzy hashes`. Unlike normal hashes, these structures are designed to hide
small differences between text patterns allowing to find similar messages quickly. Rspamd has internal storage of such hashes and can block mass spam sendings
quickly based on users' feedback. Moreover, this allows for feeding rspamd with data from [`honeypots`](http://en.wikipedia.org/wiki/Honeypot_(computing)#Spam_versions)
without polluting the statistical module.

Rspamd uses a conjunction of different techniques to make a final decision about a message. This improves the overall quality of filtering and reduces the number of
false positives (i.e. when a innocent message is incorrectly classified as spam). I have tried to simplify rspamd usage by adding the following elements:

* **Web interface** - rspamd is shipped with a fully functional ajax-based web interface that allows for observing rspamd statistics; configuring rules, weights and lists; scanning
and learning messages and viewing the history of scans. The interface is self-hosted, requires zero configuration and follows the recent web applications standards. You don't need a
web server or application server to run the web UI - you just need to run rspamd itself.

* **Integration with MTA** - rspamd can work with the most popular mail transfer systems, such as postfix, exim or sendmail. For postfix and sendmail, there is the [`rmilter` project](https://github.com/vstakhov/rmilter),
whilst for exim there are several solutions to work with rspamd. Should you require MTA integration then please consult with the [integration guide]({{ site.url }}{{ site.baseurl }}/doc/integration.html).

* **Extensive Lua API** - rspamd ships with hundreds of [lua functions]({{ site.url }}{{ site.baseurl }}/doc/lua) that are available to write one's own rules for efficient and targeted spam filtering.

* **Dynamic tables** - rspamd supports `dynamic maps` containing strings or IP addresses that are checked during runtime and updated in memory when changed. Maps can be stored on disk or accessed over HTTP/HTTPS.

## Performance

Rspamd is designed to be fast. The core of rspamd is written in `C` and uses an event-driven model that allows for processing multiple messages simultaneously without blocking.
Moreover, a set of techniques is used in rspamd to process messages faster:

* **Finite state machines processing** - rspamd uses specialized finite state machines for performance critical tasks to process input faster than a set of regular expressions.
Of course, it is possible to implement these machines by ordinary `perl regular expressions` but then they won't be compact or human-readable. On the contrary, rspamd optimizes
actions such as headers processing, received elements extraction & protocol operations by building the concrete automata for an assigned task.

* **Expressions optimizer** - optimizes expressions through execution of `likely false` or `likely true` expressions in order in the branches. This reduces the number of
expensive expressions calls when scanning a message.

* **Symbols optimizer** - rspamd tries to check frequently matched or computationally inexpensive rules first which allows for blocking spam before processing of
expensive rules (rules with negative weights are always checked first).

* **Event driven model** - rspamd is designed not to block anywhere in the code and knowing that a spam check requires a lot of network operations, rspamd can process many messages
simultaneously increasing the efficiency of shared DNS caches and other system resources. Moreover, event-driven system normally scales automatically and you won't need to do any
tuning in most cases.

* **Hyperscan regular expressions engine** - rspamd utilizes [hyperscan](https://01.org/hyperscan) engine to match multiple regular expressions at the same time. You can read the following [presentation](https://highsecure.ru/rspamd-hyperscan.pdf) where the main benefits of hyperscan are described.

* **Clever choice of data structures** - rspamd tries to use the optimal data structure for each task. For example it uses very efficient suffix tries for fast matching of a text
against a set of multiple patterns & radix bit trie for storing IP addresses information which provides O(1) access time complexity.

## Extensions

Besides its `C` core, rspamd provides an extensive [Lua](http://lua.org) API to access almost all the features available directly from `C`. Lua is an extremely easy
to learn programming language though it is powerful enough to implement complex mail filters. In fact rspamd has a significant amount of code written completely in Lua such as
DNS blacklists checks, user's settings or different maps implementation. You can also write your own filters and rules in Lua adapting rspamd's functionality to your needs.
Furthermore, Lua programs are very fast and their performance is rather [close](http://attractivechaos.github.io/plb/) to pure `C`. However, you should note that for the most
performance critical tasks you usually use the rspamd core functionality than Lua code. Anyway, you can also use `LuaJIT` with rspamd if your goal is maximum performance.
Functionality supported by the Lua API includes:

* **Reading configuration parameters** - Lua code has full access to the parsed configuration knobs and you can easily modify your plugin's behaviour through the main
rspamd configuration

* **Registering custom filters** - it is very simple to add your own filters to rspamd: just add a new index to the global variable `rspamd_config`:

~~~lua
rspamd_config.MYFILTER = function(task)
-- Do something
end
~~~

* **Full access to the content of messages** - you can access text parts, headers, SMTP data and so on and so forth by using the `task` object. The full list of methods can be found
[here]({{ site.url }}{{ site.baseurl }}/doc/lua/task.html).


* **Pre- and post- filters** - you can register callbacks that are called before or after messages processing to make results more precise or to make some early decision,
for example to implement a rate limit.

* **Registering functions for rspamd** - you can write your own functions in Lua to extend rspamd's internal expression functions.

* **Managing statistics** - Lua scripts can define a set of statistical files to be scanned or learned for a specific message allowing to create complex
statistical systems, e.g. based on an input language.

* **Standalone Lua applications** - you can even write your own worker based on rspamd core and performing some asynchronous logic in Lua. Of course, you can use the
all features from rspamd core, including such features as non-blocking IO, HTTP client and server, non-blocking redis client, asynchronous DNS, UCL configuration and so on
and so forth.

* **API documentation** - rspamd Lua API has [extensive documentation]({{ site.url }}{{ site.baseurl }}/doc/lua) where you can find examples, references and the guide about how to extend
rspamd with Lua.


## References

* Home site: <https://rspamd.com>
* Development: <https://github.com/vstakhov/rspamd>
