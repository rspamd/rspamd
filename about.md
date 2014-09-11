---
layout: default
title: About rspamd
---

## Introduction
Rspamd is a complex spam filter that allows evaluation of messages by a number of
rules including regular expressions, statistical analysis and custom services
such as URL black lists. Each message is analysed by rspamd and given a `spam score`. 

According to this spam score and the user's settings rspamd recommends an action for
the MTA to apply to the message- for example to pass, reject or add a header.
Rspamd is designed to process hundreds of messages per second simultaneously and has a number of 
features available.

## Spam filtering features {#features}

Rspamd distribution contains a number of mail processing features, including such techniques as:

* **Regular expressions filtering** - allows basic processing of messages, their textual parts, MIME headers and
SMTP data received by MTA against a set of expressions that includes both normal regular expressions and 
message processing functions. Rspamd expressions are the powerful tool that allows to filter messages based on
some pre-defined rules. This feature is similar to regular expressions in spamassassin spam filter.


* **SPF module** that allows to validate a message's sender against the policy defined in the DNS record of sender's domain. You can read
about SPF policies [here](http://www.openspf.org/). A number of mail systems includes SPF support, such as `gmail` or `yahoo mail`.


* **DKIM module** validates message's cryptographic signature against public key placed in the DNS record of sender's domain. Like SPF,
this technique is widely spread and allows to validate that a message is sent from that specific domain.


* **DNS black lists** allows to estimate reputation of sender's IP address or network. Rspamd uses a number of DNS lists including such lists as
`SORBS` or `spamhaus`. However, rspamd doesn't trust any specific DNS list and use a conjunction of estimations instead that allows to
avoid mistakes and false positives. Rspamd also uses positive and grey DNS lists for checking for trusted senders.


* **URL black lists** are rather similar to DNS black lists but uses URLs in a message to make an estimation of sender's reputation.
This technique is very useful for finding malicious or phished domains and filter such mail.


* **Statistics** - rspamd uses bayesian classifier based on five-gramms of input. This means that the input is estimated not based on individual
words, but all input is organized in chains that are further estimated by bayesian classifier. This approach allows to achieve better results than
traditionally used monogramms (or words literally speaking), that is described in details in the following [paper](http://osbf-lua.luaforge.net/papers/osbf-eddc.pdf).


* **Fuzzy hashes** - for checking of malicious mail patterns rspamd uses so called `fuzzy hashes`. Unlike normal hashes, these structures are targeted to hide
small differences between text patterns allowing to find similar messages quickly. Rspamd has internal storage of such hashes and allows to block mass spam sendings
quickly based on user's feedback that specifies messages reputation. Moreover, it allows to feed rspamd with data from [`honeypots`](http://en.wikipedia.org/wiki/Honeypot_(computing)#Spam_versions)
without polluting the statistical module.

Rspamd uses the conjunction of different techniques to make the finall decision about a message. This allows to improve the overall quality of filtering and reduce the number of
false positives (e.g. when a innocent message is badly classified as a spam one). I have tried to simplify rspamd usage by adding the following elements:

* **Web interface** - rspamd is shipped with the fully functional ajax based web interface that allows to observe rspamd statistic; to configure rules, weights and lists; to scan
and learn messages and to view the history of scans. The interface is self-hosted, requires zero configuration and follows the recent web applications standards. You don't need a
web server or applications server to run web UI - you just need to run rspamd itself and a web browser.


* **Integration with MTA** - rspamd can work with the most popular mail transfer systems, such as postfix, exim or sendmail. For postfix and sendmail, there is an [`rmilter` project](https://github.com/vstakhov/rmilter),
whilst for exim there are several sollutions to work with rspamd. Should you require MTA integration then please consult with the [integration guide](https://rspamd.com/doc/integration.html).


* **Easy configuration** - rspamd uses [`UCL` language](https://github.com/vstakhov/libucl) for configuration. UCL is a simple and intuitive language that is focused on easy to read configuration files.
You have many choices to write your definitions, so use whatever you like (even a strict `JSON` would be OK).

* **Dynamic tables** - rspamd allows to specify some data as `dynamic maps` that are checked in runtime with updating data when they are changed. Rspamd supports file and HTTP maps.

## Performance {#performance}

Rspamd was designed to be fast. The core of rspamd is written in `C` and uses event's driven model that allows to process multiple messages simultaenously and without blocking.
Moreover, a set of techniques was used in rspamd to process messages faster:

* **Finite state machines processing** - rspamd uses specialized finite state machines for the performance critical tasks to process input faster than a set of regular expressions.
Of course, it is possible to implement these machines by ordinary `perl regular expressions` but then they won't be compact or human-readable. On the contrary, rspamd optimizes
such actions as headers processing, received elements extraction, protocol operations by builiding the conrete automata for an assigned task.

* **Expressions optimizer** - allows to optimize expressions by exectution of `likely false` or `likely true` expressions in order in the branches. That allows to reduce number of
expensive expressions calls when scanning a message.

* **Symbols optimizer** - rspamd tries to check first the rules that are frequent or inexpensive in terms of time or CPU resourses, which allows to block spam before processing of
expensive rules (rules with negative weights are always checked before other ones).

* **Event driven model** - rspamd is designed not to block anywhere in the code and counting that spam checks requires a lot of network operations, rspamd can process many messages
simultaneously increasing the efficiency of shared DNS caches and other system resources. Moreover, event-driven system normally scales automatically and you won't need to do any
tuning in the most of cases.

* **Threaded expressions and statistics** - rspamd allows to perform computation resources greedy tasks, such as regular expressions or statistics, in separate threads pools, which
allows to scale even more on the modern multi-core systems.

* **Clever choice of data structures** - rspamd tries to use the optimal data structure for each task, for example, it uses very efficient suffix tries for fast matching of a text
against a set of multiple patterns. Or it uses radix bit trie for storing IP addresses information that provides O(1) access time complexity.

## Extensions

All these features allow rspamd to process messages fast and demonstrate 
accurate spam filtering. 

## References

* Home site: <https://rspamd.com>
* Development: <https://github.com/vstakhov/rspamd>
