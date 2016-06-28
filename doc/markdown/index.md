# Rspamd documentation project

## Introduction
Rspamd is a fast and advanced spam filtering system. It is based on an event-driven processing model which allows it to work with multiple messages simultaneously without blocking anywhere during message processing. Rspamd contains various modules shipped in the default distribution and allows extension with custom modules and rules written in [Lua](http://lua.org).

Rspamd uses a complex estimation system based on a set of rules. Each of these rules has its own score and the final score of a message is defined as the sum of the scores that were true for that message. This approach is similar to other complex spam filtering systems, such as [SpamAssassin](http://spamassassin.apache.org). Rspamd also implements fuzzy logic, including fuzzy hashes and a statistics module, to process messages.

## Table of Contents

- [Tutorials](tutorials/) a collection of tutorial-like documents for rspamd
- [Architecture](architecture/) presents the architecture of rspamd and explains how spam filtering is performed
- [Rspamd configuration](configuration/) describes the principles of rspamd configuration
- [Modules](modules/) lists rspamd modules and defines their configuration attributes
- [Workers](workers/) describes worker processes that are implemented in rspamd
- [Lua API](lua/) explains how to extend rspamd with lua modules
- [Migration](migration.md) contains the list of incompatible changes between rspamd versions and recommendations on how to update your rspamd system
