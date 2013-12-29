# Rspamd documentation project

## Introduction
Rspamd is a fast and advanced spam filtering system. It is based on event-driven processing model
allowing to work with multiple messages simultaneously without blocking anywhere during messages
processing. Rspamd contains various modules shipped in the default distribution and permits to be
extended with the own custom modules and rules written in [Lua](http://lua.org) programming language.
Rspamd uses complex estimation system based on a set of rules, each of those rules has its own score and
the final score of a message is defined by a sum of rules' scores that were true for that message. This approach
is similar to other complex spam filtering systems, such as [SpamAssassin](http://spamassassin.apache.org).
At the same time, rspamd uses fuzzy logic to process unknown messages. That includes fuzzy hashes and 
statistics module.

## Table of Contents
This document contains the basic documentation for rspamd spam filtering system. It is divided into the following
parts:

- [Architecture](architecture/) presents the architecture of rspamd and how spam filtering is performed
- [Rspamd configuration](configuration/) describes principles of rspamd configuration
- [Modules](modules/) chapter lists rspamd modules and defines their configuration attributes
- [Workers](workers/) section describes workers that are implemented in the rspamd
- [Lua API](lua/) explains how to extend rspamd with own lua modules