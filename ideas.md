---
layout: default
title: Rspamd project ideas
---

# Rspamd project ideas

## Introduction

This page is intended for those who are interested in contribution to rspamd. In particular, this page might be useful for those who are going to participate in Google Summer of Code programm. However, this is not limited by this purpose,
since we appreciate any valuable contributions to rspamd project.

## Information for GSoC participants

Prospective students are required to have [a github account](https://github.com), carefully examine the [rspamd source repository](https://github.com/vstakhov/rspamd) and join our discussion IRC channel: #rspamd at irc.freenode.net. All projects suggested requires medium to advanced knowledge in either *C* or *Lua* programming languages. We encourage picking projects which you feel you can realistically do within the 12-week timeline.

List of mentors available for the project via IRC and Google groups mailing list:

|---
| Mentor | IRC nick | Role
|:-|:-|-:|
| Vsevolod Stakhov | cebka | Mentor, Organization Administrator
| Andrej Zverev | az | Mentor, Backup Administrator
| Andrew Lewis | notkoos | Mentor
| Alexey Savelyev | AL | Mentor

## List of projects available

Here is the list of projects that are potentially useful for rspamd. However, students are encouraged to suggest their own project assuming they could provide reasonable motivation for it.

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

* Difficulty: medium
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

* Difficulty: medium
* Required skills: strong skills in C, intermediate skills in Lua
* Possible mentors: cebka, notkoos

* We suppose that at the midterm evaluation, we could estimate the following:
	- the basic neural network implementation model (e.g. RBF ANN);
	- the possibility to learn from result symbols of known messages;
* At the final evaluation we suppose to have the following tasks being done:
	- implement other ANN models and evaluate their learning curve;
	- adjust generated meta-rules weight according to the evidence of rules.

### Create a dedicated library for rspamd client

So far, rspamd includes a client library but it depends on the whole rspamd code making it hard or even impossible to use it in other projects. We want this library to be cut from rspamd in the way similar to separating of [rdns](https://github.com/vstakhov/rdns). Ideally, we also want SWIG bindings for the client library allowing to use it in other programming languages. Moreover, the client library should be able to work in both non-blocking (streaming) and blocking modes without explicit dependency on the exact reactor library, such as libevent.

* Difficulty: low to medium
* Required skills: intermediate skills in C
* Possible mentors: cebka, az

* We suppose that at the midterm evaluation, we could estimate the following:
	- the separate implementation of rspamdclient in C using abstract events model;
	- the ability to interact with rspamd both for scanning and learning;
* At the final evaluation we suppose to have the following tasks being done:
	- HTTPCrypt encryption support, replay attacks protection, nonces policy selection;
	- SWIG bindings to another languages

### Create functional test framework

Currently, rspamd lacks of functional testing. The idea is to create a simple testing framework in lua to make rspamd configurations, specific messages and run rspamd with the desired arguments to test a set of rspamd features. Furthermore, we could add such a tests for each commit or issue fixed to ensure that the code is covered with tests. This task also requires to modify rspamd code to work in streaming mode: e.g. to start, execute some particular task, output result and terminate.

* Difficulty: low to medium
* Required skills: good skills in Lua, some knowledge of C
* Possible mentors: notkoos, AL

* We suppose that at the midterm evaluation, we could estimate the following:
	- the testing framework that can run rspamd, generate configs, grab messages and evaluate test cases;
	- rspamd should be able to run in pipe mode to be tested more quickly;
* At the final evaluation we suppose to have the following tasks being done:
	- The most of rspamd components should have the correspoding tests in the framework;
	- The code coverage by tests must be more than 50%

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

* Difficulty: medium to high
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
