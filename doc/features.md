---
layout: default
title: Rspamd features
---

# Rspamd features

Rspamd is a complex spam filter that allows to estimate messages by many rules, statistical data and custom services like URL black lists. 
Each message is estimated by rspamd and got so called `spam score`. 
According to spam score and a user`s settings rspamd send recommended action for this message to MTA.

Rspamd has own unique features among spam filters:

* event driven architecture allowing to process many messages at a time
* flexible syntax of rules allowing to write rules in lua language
* a lot of plugins and rules shipped with rspamd distribution
* highly optimized mail processing
* advanced statistic

All these features allow rspamd to process messages fast and make good results in spam filtering.
