---
layout: default
title: Rspamd project ideas
---

# Rspamd project ideas

## Introduction

This page is intended for those who are interested in contribution to rspamd. In particular, this page might be useful for those who are going to participate in Google Summer of Code programm. However, this is not limited by this purpose,
since we appreciate any valuable contributions to rspamd project.

## Information for GSoC participants

Prospective students are required to have [a github account](https://github.com) and join our discussion IRC channel: #rspamd at irc.freenode.net. All projects suggested requires medium to advanced knowledge in either *C* or *Lua* programming languages. We encourage picking projects which you feel you can realistically do within the 12-week timeline.

List of mentors available for the project via IRC and Google groups mailing list:

|---
| Mentor | IRC nick | Role
|:-|:-:|-:|
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

### Autolearning for statistics

So far, rspamd has no ways to organize autolearning. There are many reasons why the naive approach of automatical learning based on a messages' overall score won't work in general. However, there are many unsupervised machine learning algorithms to classify the sets of messages that are suitable for automatic learning. It would be good to apply these technuques to rspamd for better statistics learning.

* Difficulty: medium
* Required skills: intermediate skills in C, intermediate skills in Lua
* Possible mentors: cebka

### Improve Lua API interaction

The current model of rspamd Lua API is rather deprecated and we propose to make it more comfortable for end users by using of tables as parameters list and improving the documentation system.

* Difficulty: low
* Required skills: intermediate skills in C, intermediate skills in Lua and Perl
* Possible mentors: az, AL

### Implement meta-statistics algorithm

We assume that for better filtering it is possible to apply supervised machine learning algorithms, such as neural networks to provide meta-classification rules based on the prior knowledge of symbols combinations influence on the messages class. In theory, this method should provide
a very flexible way to train filter against repeated spam patterns. Unlike traditional methods, it requires almost zero additional computations and can be learned automatically instead of writing meta-rules.

* Difficulty: medium
* Required skills: strong skills in C, intermediate skills in Lua
* Possible mentors: cebka, notkoos

### Create a dedicated library for rspamd client

So far, rspamd includes a client library but it depends on the whole rspamd code making it hard or even impossible to use it in other projects. We want this library to be cut from rspamd in the way similar to separating of [rdns](https://github.com/vstakhov/rdns). Ideally, we also want SWIG bindings for the client library allowing to use it in other programming languages. Moreover, the client library should be able to work in both non-blocking (streaming) and blocking modes without explicit dependency on the exact reactor library, such as libevent.

* Difficulty: low to medium
* Required skills: intermediate skills in C
* Possible mentors: cebka, az

### Create functional test framework

Currently, rspamd lacks of functional testing. The idea is to create a simple testing framework in lua to make rspamd configurations, specific messages and run rspamd with the desired arguments to test a set of rspamd features. Furthermore, we could add such a tests for each commit or issue fixed to ensure that the code is covered with tests. This task also requires to modify rspamd code to work in streaming mode: e.g. to start, execute some particular task, output result and terminate.

* Difficulty: low to medium
* Required skills: good skills in Lua
* Possible mentors: notkoos, AL

### Improve libucl bindings to other languages

Libucl, being the crucial component of rspamd, lacks of bindings to other languages. The idea is to implement the following bindings: a generic bindings using SWIG, a specific C++ bindings using modern C++11 for high performance appliances. The benefit from this task is also in organizing bridge from rspamd to many languages using just UCL objects.

* Difficulty: low to medium
* Required skills: C, C++ (and C++11 in particular), SWIG
* Possible mentors: cebka, az

### Support of HTTPCrypt in the Web interface

Currently, rspamd supports opportunistic encryption of all messages. However, the web interface does not support encryption at all. The idea is to grab [libsodium-js](https://github.com/jedisct1/libsodium.js) and adopt its primitives for rspamd cryptobox (namely, replacing salsa20 with chacha20 and slight poly1305 authenticator modification).

* Difficulty: medium
* Required skills: Javascript
* Possible mentors: cebka
