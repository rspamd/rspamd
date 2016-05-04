--- 
layout: default
title: About rspamd
---

## Introduction

Rspamd is an advanced spam filtering system that allows evaluation of messages by a number of rules including regular expressions, statistical analysis and custom services such as URL black lists. Each message is analysed by rspamd and given a `spam score`.

According to this spam score, and the user's settings, rspamd recommends an action for the MTA to apply to the message - for example to pass, reject or add a header. Rspamd is designed to process hundreds of messages per second simultaneously and has a number of features available.

## Spam filtering features {#features}

The rspamd distribution contains a number of mail processing features, including such techniques as:

* **Regular expressions filtering** - allows basic processing of messages, their textual parts, MIME headers and SMTP data received by the MTA against a set of expressions that includes both normal regular expressions and message processing functions. Rspamd expressions are a powerful tool that allows message filtering based on pre-defined rules. This feature is similar to regular expressions in the spamassassin spam filter. Moreover, rspamd supports Spamassassin rules directly via [the plugin](https://rspamd.com/doc/modules/spamassassin.html).


* **SPF module** which validates a message's sender against the policy defined in the DNS record of the sender's domain. You can read about SPF policies [here](http://www.openspf.org/). A number of mail systems, such as `gmail` or `yahoo mail`, include SPF support.


* **DKIM module** validates a message's cryptographic signature against a public key placed in the DNS record of the sender's domain. Like SPF, this technique is widespread and allows validation that a message is sent by a specific domain.

* **DMARC module** validates the joint SPF and DKIM policies for a sender and evaluates if there are additional restrictions. Rspamd also supports storing report data within [redis](http://redis.io) storage.


* **DNS black lists** allows estimation of the reputation of a sender's IP address or network. Rspamd uses a number of DNS lists including such lists as `SORBS` and `spamhaus`. However, rspamd doesn't trust any specific DNS list and use a conjunction of estimates instead to avoid mistakes and false positives. Rspamd also uses positive and grey DNS lists to check for trusted senders.


* **URL black lists** are similar to DNS black lists but use URLs in a message to estimate a sender's reputation. This technique is very useful for finding malicious or phishing domains and filter such mail.


* **Statistics** - rspamd uses a Bayesian classifier based on five-grams of input. This means that the input is estimated not based on individual words, but all input is organized in chains that are further estimated by the Bayesian classifier. This approach enables better results than traditional unigrams (or words, literally speaking). The approach is described in detail in the following [paper](http://osbf-lua.luaforge.net/papers/osbf-eddc.pdf).


* **Fuzzy hashes** - rspamd uses so-called `fuzzy hashes` to check for malicious mail patterns. Unlike normal hashes, a fuzzy hash can ignore small differences between text patterns and can be used to find similar messages quickly. Rspamd uses internal storage of fuzzy hashes and blocks mass spam sendings quickly based on user feedback to rate message reputation. It also allows the feeding of rspamd with data from [`honeypots`](http://en.wikipedia.org/wiki/Honeypot_(computing)#Spam_versions) without polluting the statistical module.

Rspamd uses a blend of techniques to make a final decision about a message. This improves the overall quality of filtering and reduces the number of false positives (e.g. when an innocent message is badly classified as a spam one). I have tried to simplify rspamd usage by adding the following elements:

* **Web interface** - rspamd is shipped with a fully functional ajax-based web interface that allows observation of rspamd statistic; configuration of rules, weights and lists; scanning and learning messages and viewing the scan history. The interface is self-hosted, requires zero configuration and follows recent web applications standards. You don't need a web or application server to run the web UI - you just need a running instance of rspamd and a web browser.


* **Integration with MTA** - rspamd can work with the most popular mail transfer systems, such as postfix, exim or sendmail. For postfix and sendmail, there is an [`rmilter` project](https://github.com/vstakhov/rmilter), while there are several solutions for integrating rspamd with exim. You can read more about MTA integration in the [integration guide](https://rspamd.com/doc/integration.html).


* **Easy configuration** - rspamd uses the [`UCL` language](https://github.com/vstakhov/libucl) for configuration. UCL is a simple and intuitive language that is focused on easy to read configuration files. You have many options in writing definitions, so use whatever you like (even a strict `JSON` would be OK).

* **Dynamic tables** - rspamd allows the specification of some data as `dynamic maps` which are checked in runtime, with data updated when they change. Rspamd supports file and HTTP maps.

## Performance {#performance}

Rspamd was designed to be fast. The core of rspamd is written in `C` and uses an event-driven model that allows the processing of multiple messages simultaneously without blocking. Moreover, a set of techniques was used in rspamd to speed up message processing:

* **Finite state machines** - rspamd uses specialised finite state machines for performance-critical tasks to process input faster than a set of regular expressions. Of course, it is possible to implement these machines by ordinary `perl regular expressions` but then they won't be compact or human-readable. On the contrary, rspamd optimises such actions as header processing, received elements extraction and protocol operations by building concrete automata for an assigned task.

* **Expression optimiser** - optimises expressions by the execution of `likely false` or `likely true` expressions in priority order. This reduces the number of expensive expression calls when scanning a message.

* **Symbol optimiser** - rspamd tries to first check rules that are frequent or inexpensive in terms of time or CPU resources, which allows blocking spam before the processing of expensive rules (rules with negative weights are always checked first). You can view my presentation about it [here](https://highsecure.ru/ast-rspamd.pdf).

* **Event driven model** - rspamd is designed not to block anywhere in the code. Considering that spam checks require a lot of network operations, rspamd can process many messages simultaneously thus increasing the efficiency of shared DNS caches and other system resources. Moreover, event-driven systems normally scale automatically - you won't need to do any tuning in most cases.

* **Threaded expressions and statistics** - rspamd delegates greedy tasks, such as regular expressions or statistics, to separate thread pools which brings benefits on modern multi-core systems.

* **Clever choice of data structures** - rspamd tries to use the optimal data structure for each task. For example, it uses very efficient suffix tries for fast matching of a text against a set of multiple patterns, or it uses radix bit tries for storing IP address information that provides O(1) access time complexity.

You can also check a user's report regarding rspamd performance at [haraka github](https://github.com/haraka/Haraka/pull/964#issuecomment-100694945).

## Extensions {#extensions}

Besides the `C` core, rspamd provides a [Lua](http://lua.org) API to access almost all of the features available directly from `C`. Lua is an easy to [learn](http://lua-users.org/wiki/TutorialDirectory) programming language, though it is powerful enough to implement complex mail filters. In fact, rspamd has a significant amout of code written completely in Lua, such as DNS blacklist checks, user settings and different map implementations. You can write your own filters and rules in Lua, adapting rspamd functionality to your needs. Furthermore, Lua programs are very fast and their performance is rather [close](http://attractivechaos.github.io/plb/) to pure `C`. However, you should note that for the most performance-critical tasks you would usually use the rspamd core functionality, rather than Lua code. You can also use `LuaJIT` with rspamd if your goal is maximum performance. The Lua API can be used as follows:

* **Read configuration parameters** - Lua code has full access to the parsed configuration knobs and you can easily modify your plugin's behaviour by means of the main rspamd configuration.

* **Register custom filters** - it is simple to add your own filters to rspamd: just add a new index to the global variable `rspamd_config`:

~~~lua
rspamd_config.MYFILTER = function(task)
-- Do something 
end
~~~

* **Access the content of messages** - you can access text parts, headers, SMTP data and so on using the `task` object. The full list of methods can be found [here](https://rspamd.com/doc/lua/task.html).

* **Pre- and post- filters** - you can register callbacks that are called before or after message processing to make results more precise or to make some early decision; for example, to implement a rate limit.

* **Register functions for rspamd** - you can write your own functions in Lua to extend rspamd's internal expression functions.

* **Manage statistics** - Lua scripts can define a set of statistical files to be scanned or learned for a specific message allowing the creation of more complex statistical systems, e.g. based on an input language. Moreover, you can even learn rspamd statistic from Lua scripts.

* **Standalone Lua applications** - you can even write your own worker based on rspamd core and performing some asynchronous logic in Lua. Of course, you can use all the features of rspamd core, including such features as non-blocking IO, HTTP client and server, non-blocking redis client, asynchronous DNS, UCL configuration and so on.

* **API documentation** - rspamd Lua API has [detailed documentation](https://rspamd.com/doc/lua) where you can find examples, references and a guide about how to extend rspamd with Lua.

