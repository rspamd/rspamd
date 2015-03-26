---
layout: default
title: Rspamd project ideas
---

# Rspamd project ideas

## Introduction

This page is intended for those who are interested in contribution to rspamd. In particular, this page might be useful for those who are going to participate in [Google Summer of Code program](http://www.google-melange.com/gsoc/org2/google/gsoc2015/rspamd). However, this is not limited by this purpose,
since we appreciate any valuable contributions to rspamd project.

## Information for GSoC participants

Prospective students are required to have [a github account](https://github.com), carefully examine the [rspamd source repository](https://github.com/vstakhov/rspamd) and join our discussion IRC channel: #rspamd at irc.freenode.net. All projects suggested requires medium to advanced knowledge in either *C* or *Lua* programming languages. 

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
| Alexey Savelyev | AL | | Mentor

## List of projects available

Here is the list of projects that are desired for rspamd. However, students are encouraged to suggest their own project assuming they could provide reasonable motivation for it.

### Symbols dependency graph

Currently, there is no possibility to plan checks that depends from each other. However, for certain rules it is very useful to check specific rules before others and use the results from those checks afterwards. This project is especially desired for organizing complex rules where the results of top level checks depends on the results of other checks, which could not be implemented by composites only in general.

* Difficulty: medium to hard
* Required skills: strong skills in C, basic understanding of the event based model
* Possible mentors: cebka, az

Evaluation details:

* We suppose that at the midterm evaluation, we could estimate the following:
	- build dependency graph from the configuration;
	- the symbols planning code should be able to select the order based on the dependency graph.
* At the final evaluation we suppose to have the following features implemented:
	- dependencies are integrated to both C plugins and lua API;
	- events system can carefully evaluate events cancelling according to the dependency graph;
	- cyclic dependencies should not be allowed.

### Autolearning for statistics

So far, rspamd has no ways to organize autolearning. There are many reasons why the naive approach of automatical learning based on a messages' overall score won't work in general. However, there are many unsupervised machine learning algorithms to classify the sets of messages that are suitable for automatic learning. It would be good to apply these technuques to rspamd for better statistics learning.

* Difficulty: medium to hard
* Required skills: intermediate skills in C, intermediate skills in Lua
* Possible mentors: cebka

Evaluation details:

* We suppose that at the midterm evaluation, we could estimate the following:
	- the prototype of autolearning based on scores and symbols written in lua;
	- markov chains implementation to regulate autolearning based on symbols' combinations;
* At the final evaluation we suppose to have the following tasks being done:
	- implement several machine learning algorithms (e.g. clustering or Hidden-Markov model);
	- add ability to learn from the incoming messages;
	- evaluate the quality of algorithms;
	- determine when to start autolearning.

### Implement meta-statistics algorithm

We assume that for better filtering it is possible to apply supervised machine learning algorithms, such as neural networks to provide meta-classification rules based on the prior knowledge of symbols combinations influence on the messages class. In theory, this method should provide
a very flexible way to train filter against repeated spam patterns. Unlike traditional methods, it requires almost zero additional computations and can be learned automatically instead of writing meta-rules.

* Difficulty: medium to hard
* Required skills: strong skills in C, intermediate skills in Lua
* Possible mentors: cebka, notkoos

* We suppose that at the midterm evaluation, we could estimate the following:
	- the basic neural network implementation model (e.g. RBF ANN);
	- the possibility to learn from result symbols of known messages;
* At the final evaluation we suppose to have the following tasks being done:
	- implement other ANN models and evaluate their learning curve;
	- adjust generated meta-rules weight according to the evidence of rules.

### Implement SMTP proxy mode in rspamd

There are two efforts of SMTP proxy implementations in rspamd, however, they are not finished so far. SMTP proxy is a convenient method of spam filtering that can be used with any MTA (including, for example, OpenSMTPD). Moreover, rspamd could act as a fast pre-filtering proxy to eliminate spam based on merely envelope checks (SPF, RBL and so on).

* Difficulty: medium
* Required skills: excellent skills in C, good understanding of event based data processing model
* Possible mentors: cebka

* We suppose that at the midterm evaluation, we could estimate the following:
	- the *tested* implementation of smtp full and lightweight proxies with no SMTP queue support;
* At the final evaluation we suppose to have the following tasks being done:
	- fully functional SMTP proxy that supports SMTP queue managing


### Create functional test framework

Currently, rspamd lacks of functional testing. The idea is to create a simple testing framework in lua to make rspamd configurations, specific messages and run rspamd with the desired arguments to test a set of rspamd features. Furthermore, we could add such a tests for each commit or issue fixed to ensure that the code is covered with tests. This task also requires to modify rspamd code to work in streaming mode: e.g. to start, execute some particular task, output result and terminate.

* Difficulty: easy to medium
* Required skills: good skills in Lua, some knowledge of C
* Possible mentors: notkoos, AL

* We suppose that at the midterm evaluation, we could estimate the following:
	- the testing framework that can run rspamd, generate configs, grab messages and evaluate test cases;
	- rspamd should be able to run in pipe mode to be tested more quickly;
* At the final evaluation we suppose to have the following tasks being done:
	- most of rspamd components should have the correspoding tests in the framework;
	- the code coverage by tests must be more than 50%

### Support of HTTPCrypt in the Web interface

Currently, rspamd supports opportunistic encryption of all messages. However, the web interface does not support encryption at all. The idea is to grab [libsodium-js](https://github.com/jedisct1/libsodium.js) and adopt its primitives for rspamd cryptobox (namely, replacing salsa20 with chacha20 and slight poly1305 authenticator modification).

* Difficulty: medium
* Required skills: Javascript
* Possible mentors: cebka

* We suppose that at the midterm evaluation, we could estimate the following:
	- libsodium-js should be integrated to the rspamd web UI;
	- libsodium-js should use the appropriate primitives for rspamd cryptobox;
	- we should be able to check whether controlling messages are encrypted;
* At the final evaluation we suppose to have the following tasks being done:
	- replay attacks protection, nonces policy selection;
	- encrypted HTTP sessions.

### Support for pyzor and dcc

Rspamd has no native interface to neither pyzor nor dcc. These hash storages provides reasonable amount of blacklisted patterns and could be used for filtering quality improvement. This project implies the ability to restore protocol's description based on the foreign source code (namely, in Perl or Python)

* Difficulty: medium to hard
* Required skills: strong knowledge of C, familiarity with perl or python
* Possible mentors: az, AL

* We suppose that at the midterm evaluation, we could estimate the following:
	- the protocol description of pyzor;
	- basic prototype of pyzor checking routines;
	- the protocol description for DCC;
* At the final evaluation we suppose to have the following tasks being done:
	- working code for pyzor check;
	- prototype of DCC check module

### Create migration tools for statistics

With the upcoming rspamd 0.9 release, there are plans to support various backends for the statistic tokens. However, for the long time, the only supported backend was mmap backend. In terms of this project, we propose to create an utility that can automatically convert statistics between different backends. This could be done in lua, for example, with a small support from the C side.

* Difficulty: easy
* Required skills: medium skills in Lua, basic knowledge of C
* Possible mentors: notkoos, AL

* We suppose that at the midterm evaluation, we could estimate the following:
	- the tool that can convert from mmapped files to other backends;
* At the final evaluation we suppose to have the following tasks being done:
	- the fully functional utility to migrate data from one backends to another including cases of clustering migration (e.g. from a single server to a cluster and vice-versa)

### Recursion and DNSSEC support in rdns resolver

So far, librdns library that is used for resolving names in rspamd does not support recursion relaying on the external DNS recursor. Nevertheless, the useful features of this library, for example DNSCurve support and the upcoming DNSSEC support can benefit from the own recursion implementation. This project implies good understanding of network protocols and DNS in particular as well as strong skills in C programming language.

* Difficulty: medium to hard
* Required skills: good knowledge of C, network programming
* Possible mentors: cebka

* We suppose that at the midterm evaluation, we could estimate the following:
	- recursion support in RDNS;
* At the final evaluation we suppose to have the following tasks being done:
	- DNSSEC chains of trust and DNSCurve or DNSCrypt trust model support

### Add language detection to rspamd

The current language detection system is based on merely unicode glyphs classes. This classification is quite poor, since it cannot distinguish many languages. The idea is to write an advanced language detection library, for example based on 3-gramms, and take advantage from lemmatization for a bigger set of languages. We also propose to write a more simple approach based on letters combinations as the starting point and check whether can we do better.

* Difficulty: medium
* Required skills: good knowledge of C **or** good knowledge of Lua
* Possible mentors: cebka, az

* We suppose that at the midterm evaluation, we could estimate the following:
	- the working language detection based on letters combinations;
	- the prototype of 3-gramms algrithm for better language detection.
* At the final evaluation we suppose to have the following tasks being done:
	- the working 3-gramms algorithm with trained corpus for the major languages;
	- support of transliteration detection via 3-gramms for certain languages.
