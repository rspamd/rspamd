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
some pre-defined rules. This feature is similar to regular expressions in spamassassin spam filter/
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

## Performance

* event driven architecture allowing to process many messages at a time;
* flexible syntax of rules allowing to write rules in lua language;
* a lot of plugins and rules shipped with rspamd distribution;
* highly optimised mail processing;
* advanced statistical analysis;

All these features allow rspamd to process messages fast and demonstrate 
accurate spam filtering. 

## References

* Home site: <https://rspamd.com>
* Development: <https://github.com/vstakhov/rspamd>
