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

All code contributed must have either 2 clause BSD license or any license from [this list](https://github.com/vstakhov/rspamd/blob/master/CONTRIBUTIONS.md).


#### List of mentors available for the project via IRC and Google groups mailing list:

|---
| Mentor | IRC nick | E-Mail | Role
|:-|:-|-:|:-|
| Vsevolod Stakhov | cebka | vsevolod@rspamd.com | Mentor, Organization Administrator
| Andrej Zverev | az | az@rspamd.com | Mentor, Backup Administrator
| Andrew Lewis | notkoos | notkoos@rspamd.com | Mentor

## List of projects available

Here is the list of projects that are desired for rspamd. However, students are encouraged to suggest their own project assuming they could provide reasonable motivation for it.

### XMPP filtering support

Rspamd can now be used for filtering of email messages. However, there are no obstacles in applying Rspamd for other protocols such as XMPP. We expect that during this project a prospective student will study xmpp protocol specific details and will write integration for some popular jabber servers (for example, prosody or ejabberd).

* Difficulty: medium
* Required skills: lua skills, understanding of XMPP, basic machine learning
* Possible mentors: cebka, az

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

Evaluation details:

* We suppose that at the midterm evaluation, we could estimate the following:
* At the final evaluation we suppose to have the following features implemented:

### Fast neural network implementation

So far, Rspamd uses `libfann` for the basic neural networks support (multilayer perceptron). However, this library is not optimized for the modern CPUs and has not very convenient interface. The goal of this project is to write a mininal neural networks library using the modern CPU features, such as `AVX` or `FMA` instructions if possible.

* Difficulty: high
* Required skills: strong C and assembly skills
* Possible mentors: cebka

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
* Possible mentors: cebka, smf

### WebUI plugins improvements


### Tarantool support


### Libmilter fast alternative
