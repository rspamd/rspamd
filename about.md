---
layout: default
title: About rspamd
---

Rspamd is a complex spam filter that allows evaluation of messages by a number of
rules including regular expressions, statistical analysis and custom services
such as URL black lists. Each message is analysed by rspamd and given a `spam score`. 

According to this spam score and the user's settings rspamd recommends an action for
the MTA to apply to the message- for example to pass, reject or add a header.
Rspamd has some unique features among spam filters: 

* event driven architecture allowing to process many messages at a time;
* flexible syntax of rules allowing to write rules in lua language;
* a lot of plugins and rules shipped with rspamd distribution;
* highly optimised mail processing;
* advanced statistical analysis;

All these features allow rspamd to process messages fast and demonstrate 
accurate spam filtering. 



## References

* Home site: <https://rspamd.com>
* Wiki: <https://bitbucket.org/vstakhov/rspamd/wiki/>
