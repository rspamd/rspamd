---
layout: default
title: Rspamd project ideas
---

# Rspamd project ideas

## Introduction

This page is intended for those who are interested in contribution to rspamd. In particular, this page might be useful for those who are going to participate in [Google Summer of Code program](https://developers.google.com/open-source/gsoc/). However, this is not limited by this purpose,
since we appreciate any valuable contributions to rspamd project.

## Information for GSoC participants

Prospective students are required to have [a github account](https://github.com), carefully examine the [rspamd source repository](https://github.com/vstakhov/rspamd) and join our discussion IRC channel: #rspamd at irc.freenode.net. All projects suggested requires medium to advanced knowledge in *C* and *Lua* programming languages or at least a strong desire to study the missing one (Lua will not be a problem most likely).

You should also be familiar with git version control system. Should you want to study more about git then please read the following [book](http://git-scm.com/book/en/v2). For the project itself, we suppose to clone rspamd repo to your local github account and do all job there, synchronizing with the rspamd mainline repository by means of `git rebase`.

We encourage picking projects which you feel you can **realistically** do within the **12-week** timeline. Some of the projects imply certain research work, however, we have placed the **approximate** evaluation criteria for the timeline specified by the summer of code programme. Taking such a project is a challenging task but it could improve your research skills and hence lead to a good research project.

All code contributed must be licensed under Apache 2 license.


#### List of mentors available for the project via IRC and Google groups mailing list:

|---
| Mentor | IRC nick | E-Mail | Role
|:-|:-|-:|:-|
| Vsevolod Stakhov | cebka | vsevolod@rspamd.com | Mentor, Organization Administrator
| Andrej Zverev | az | az@rspamd.com | Mentor, Backup Administrator
| Andrew Lewis | notkoos | notkoos@rspamd.com | Mentor
| Steve Freegard | smf | steve@rspamd.com | Mentor

## List of projects available

Here is the list of projects that are desired for rspamd. However, students are encouraged to suggest their own project assuming they could provide reasonable motivation for it.

- [List of projects available](#list-of-projects-available)
  - [XMPP filtering support](#xmpp-filtering-support)
  - [Dmarc reporting](#dmarc-reporting)
  - [Fast neural network implementation](#fast-neural-network-implementation)
  - [HTTPS server support](#https-server-support)
  - [WebUI plugins improvements](#webui-plugins-improvements)
  - [Tarantool support](#tarantool-support)
  - [Libmilter fast alternative](#libmilter-fast-alternative)
  - [Bayes signatures](#bayes-signatures)

### XMPP filtering support

Rspamd can now be used for filtering of email messages. However, there are no obstacles in applying Rspamd for other protocols such as XMPP. We expect that during this project a prospective student will study xmpp protocol specific details and will write integration for some popular jabber servers (for example, prosody or ejabberd).

* Difficulty: medium
* Required skills: lua skills, understanding of XMPP, basic machine learning
* Possible mentors: cebka, az

Benefits for a student:

Evaluation details:

* We suppose that at the midterm evaluation, we could estimate the following:
	- basic integration with one of jabber servers,
	- basic adoption of Rspamd to filter XMPP messages.
* At the final evaluation we suppose to have the following features implemented:
	- full integration with one or two jabber servers,
	- XMPP specific rules, plugins and configuration for fast deployment

### Dmarc reporting

Rspamd currently supports storing DMARC reports in the Redis server. However, there are no convenient tools to use that data and send cumulative reports to the appropriate domains. This project is intended to fix this issue.

* Difficulty: medium
* Required skills: lua skills, email standards understanding
* Possible mentors: notkoos

Benefits for a student:

A successful candidate will learn about email protocols, Lua programming language and Redis database.

Evaluation details:

* We suppose that at the midterm evaluation, we could estimate the following:
	- basic implementation of the reports collector that is able to grab data from Redis and send a report
	- a tool to test reports collection written in any language
* At the final evaluation we suppose to have the following features implemented:
	- full implementation of the collector that can interact with the real collection points

### Fast neural network implementation

So far, Rspamd uses `libfann` for the basic neural networks support (multilayer perceptron). However, this library is not optimized for the modern CPUs and has not very convenient interface. The goal of this project is to write a mininal neural networks library using the modern CPU features, such as `AVX` or `FMA` instructions if possible.

* Difficulty: high
* Required skills: strong C and assembly skills
* Possible mentors: cebka

Benefits for a student:

Upon completing of this project, a student will study how to write optimized algorithms using the modern CPU features, and will learn more about neural networks and their training.

Evaluation details:

* We suppose that at the midterm evaluation, we could estimate the following:
	- a minimal working prototype for multilayer perceptron and quick backpropagation algorithm for training
* At the final evaluation we suppose to have the following features implemented:
	- a full library is written with dynamic dispatching of vectorized instructions depending on CPU
	- benchmarks are done to compare `libfann` and the new implementation

### HTTPS server support

Rspamd HTTP library supports client mode of HTTPS and server mode with HTTPCrypt. However, in some cases, the usage of HTTPCrypt is not possible due to client's restriction and HTTPS is the only sane choice. Rspamd should be able to support HTTPS as a secure server.

* Difficulty: medium
* Required skills: strong C skills, experiences with openssl and secure programming principles
* Possible mentors: cebka, az

Benefits for a student:

Upon completing of this project, a student will know more about secure protocols and OpenSSL library internals as well as low level C programming.

Evaluation details:

* We suppose that at the midterm evaluation, we could estimate the following:
	- basic HTTPS support on server side of the HTTP library
* At the final evaluation we suppose to have the following features implemented:
	- support for multiple certs, client certificates and ciphers selection
	- certificates generation tool using `rspamadm`

### WebUI plugins improvements

Currently, Rspamd has support to execute plugins callbacks from Lua plugins and return data to WebUI. The idea of this project is to improve support of this method by adding the corresponding functions to the existing plugins:

- surbl (extract URLs)
- fuzzy check (generate hashes)
- multimap (update or check data)
- dkim check (sign a message)
- whitelist (manage lists)

These features are highly demanded by Rspamd users.

* Difficulty: easy
* Required skills: Javascript, Lua
* Possible mentors: notkoos, cebka

Benefits for a student:

Upon completing of this project, a student will have more experiences with Web development, Javascript and Lua programming languages.

Evaluation details:

* We suppose that at the midterm evaluation, we could estimate the following:
	- support of at least 3 plugins in WebUI
* At the final evaluation we suppose to have the following features implemented:
	- support of all plugins with useful configuration in WebUI

### Tarantool support

Rspamd now supports Redis to store all data. [Tarantool](https://tarantool.org) is an excellent modern alternative to Redis providing SQL like interface, more sophisticated data storage with transactions and ACID guarantees as well as Lua scripting support on the server side. Since Rspamd supports message pack (using libucl) it might be a good idea to add Tarantool support to Rspamd for certain (or even all) data.

* Difficulty: medium/hard
* Required skills: Lua, C
* Possible mentors: notkoos, cebka, az

Benefits for a student:

Upon completing of this project, a student will have knowledge in NoSQL systems, data serialization formats and Lua scripting

Evaluation details:

* We suppose that at the midterm evaluation, we could estimate the following:
	- support of Tarantool in C and LuaAPI for Tarantool calls
	- statistics in Tarantool
* At the final evaluation we suppose to have the following features implemented:
	- architecture to support dual backends: Redis and Tarantool
	- adoption of plugins
	- fuzzy storage backend in Tarantool

### Libmilter fast alternative

Rspamd milter integration, namely `rmilter` has been created using `libmilter` library. This library is being developped as a part of the Sendmail project and has different design flaws that are unevitable when using `libmilter`. For example, it proposes using of threads but does not follow the normal `N:N` model migrating tasks between threads. This makes the development of `Rmilter` constrained to `libmilter` model. The idea of this project is to implement the Sendmail milter protocol from the scratch. Unlike the original libmilter, this library should not enforce specific IO model to the milters designers (namely, threading model).

The second part of the task is to add milter support to Rspamd. The current stale project lives [here](https://github.com/vstakhov/librmilter).

* Difficulty: medium/hard
* Required skills: strong C skills
* Possible mentors: cebka, az

Benefits for a student:

Upon completing of this project, a student will have knowledge in networking, sockets, low level C programming and event driven state machines

Evaluation details:

* We suppose that at the midterm evaluation, we could estimate the following:
	- basic milter protocol support
	- a simple milter and tests framework to test protocol messages and macros
* At the final evaluation we suppose to have the following features implemented:
	- milter support is fully functional inside Rspamd

### Bayes signatures

Rspamd has a powerful [statistical module](https://rspamd.com/doc/configuration/statistic.html) which uses Bayes classifier to detect spam messages. We want to allow relearning or retraining of messages using bayes signatures. The idea behind such a signature is to store unique message tokens and associate them with some random string (e.g. using Redis). Afterwards, this string could be inserted into the message allowing to extract tokens when they are needed without having the full message's body. This feature is very useful for eliminating bayes false positives without having to ask users to provide the full messages samples which could contain sensitive information.

* Difficulty: medium
* Required skills: C skills
* Possible mentors: smf

Benefits for a student:

Upon completing of this project, a student will have basic understanding of the Bayes classifier, text tokenization principles and C language development.

Evaluation details:

* We suppose that at the midterm evaluation, we could estimate the following:
	- Bayes signatures generation and storage
* At the final evaluation we suppose to have the following features implemented:
	- the ability to learn Bayes classifier using signatures
	- support of adding signatures to messages
	- WebUI support of Bayes signatures