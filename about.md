---
layout: default
title: About rspamd
---

Rspamd is a complex spam filter that allows to estimate messages by a number of
rules including regular expression, statistical analysis and custom services,
such as URL black lists. Each message is analysed by rspamd and got a *spam
score*. 

According to this spam score and user's settings rspamd recommends to apply an
action for this message to MTA, for example to pass, to reject or to add spam
header. Rspamd has own unique features among spam filters: 

* event driven architecture allowing to process many messages at a time;
* flexible syntax of rules allowing to write rules in lua language;
* a lot of plugins and rules shipped with rspamd distribution;
* highly optimized mail processing;
* advanced statistic;

All these features allow rspamd to process messages fast and demonstrate a
suitable spam filtering. 



## References

* Home site: <http://rspamd.com>
* Downloads: <https://bitbucket.org/vstakhov/rspamd/downloads>
* Wiki: <https://bitbucket.org/vstakhov/rspamd/wiki/>
