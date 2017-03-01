---
layout: doc_arch
title: Rspamd Architecture
---
# Rspamd architecture

## Introduction

Rspamd is a universal spam filtering system based on an event-driven processing model, which means that Rspamd is not intended to block anywhere in the code. To process messages Rspamd uses a set of `rules`. Each `rule` is a symbolic name associated with a message property. For example, we can define the following rules:

- `SPF_ALLOW` - means that a message is validated by SPF;
- `BAYES_SPAM` - means that a message is statistically considered as spam;
- `FORGED_OUTLOOK_MID` - message ID seems to be forged for the Outlook MUA.

Rules are defined by [modules](../modules/). If there is a module, for example, that performs SPF checks it may define several rules according to SPF policy:

- `SPF_ALLOW` - a sender is allowed to send messages for this domain;
- `SPF_DENY` - a sender is denied by SPF policy;
- `SPF_SOFTFAIL` - there is no affinity defined by SPF policy.

Rspamd supports two main types of modules: internal modules written in C and external modules written in Lua. There is no real difference between the two types with the exception that C modules are embedded and can be enabled in a `filters` attribute in the `options` section of the config:

~~~ucl
options {
 filters = "regexp,surbl,spf,dkim,fuzzy_check,chartable,email";
 ...
}
~~~

## Protocol

Rspamd uses the HTTP protocol for all operations. This protocol is described in the [protocol section](protocol.html).

## Metrics

Rules in Rspamd define a logic of checks, but it is required to set up weights for each rule. (For Rspamd, weight means `significance`.) Rules with a greater absolute value of weight are considered more important. The weight of rules is defined in `metrics`. Each metric is a set of grouped rules with specific weights. For example, we may define the following weights for our SPF rules:

- `SPF_ALLOW`: -1
- `SPF_DENY`: 2
- `SPF_SOFTFAIL`: 0.5

Positive weights mean that this rule increases a messages 'spammyness', while negative weights mean the opposite.

### Rules scheduler

To avoid unnecessary checks Rspamd uses a scheduler of rules for each message. If a message is considered as definite spam then further checks are not performed. This scheduler is rather naive and it performs the following logic:

- select negative rules *before* positive ones to prevent false positives;
- prefer rules with the following characteristics:
  - frequent rules;
  - rules with more weight;
  - faster rules

These optimizations can filter definite spam more quickly than a generic queue.

Since Rspamd-0.9 there are further optimizations for rules and expressions that are described generally in the [following presentation](http://highsecure.ru/ast-rspamd.pdf).

## Actions

Another important property of metrics is their actions set. This set defines recommended actions for a message if it reaches a certain score defined by all rules which have been triggered. Rspamd defines the following actions:

- `No action`: a message is likely to be ham;
- `Greylist`: greylist a message if it is not certainly ham;
- `Add header`: a message is likely spam, so add a specific header;
- `Rewrite subject`: a message is likely spam, so rewrite its subject;
- `Reject`: a message is very likely spam, so reject it completely

These actions are just recommendations for the MTA and are not to be strictly followed. For all actions that are greater or equal than `greylist` it is recommended to perform explicit greylisting. `Add header` and `rewrite subject` actions are very close in semantics and are both considered as probable spam. `Reject` is a strong rule which usually means that a message should be really rejected by the MTA. The triggering score for these actions should be specified according to their logic priorities. If two actions have the same weight, the result is unspecified.

## Rules weight

The weight of rules is not necessarily constant. For example, for statistics rules we have no certain confidence if a message is spam or not; instead we have a measure of probability. To allow fuzzy rules weight, Rspamd supports `dynamic weights`. Generally, it means that a rule may add a dynamic range from 0 to a defined weight in the metric. So if we define the symbol `BAYES_SPAM` with a weight of 5.0, then this rule can add a resulting symbol with a weight from 0 to 5.0. To distribute values, Rspamd uses a form of Sigma function to provide a fair distribution curve. The majority of Rspamd rules, with the exception of fuzzy rules, use static weights.

## Statistics

Rspamd uses statistic algorithms to precisely calculate the final score of a message. Currently, the only algorithm defined is OSB-Bayes. You can find details of this algorithm in the following [paper](http://osbf-lua.luaforge.net/papers/osbf-eddc.pdf). Rspamd uses a window size of 5 words in its classification. During the classification procedure, Rspamd splits a message into a set of tokens. Tokens are separated by punctuation or whitespace characters. Short tokens (less than 3 symbols) are ignored. For each token, Rspamd calculates two non-cryptographic hashes used subsequently as indices. All these tokens are stored in different statistics backends (mmapped files, SQLite3 database or Redis server). Currently, the recommended backend for statistics is `Redis`.

## Running rspamd

There are several command-line options that can be passed to rspamd. All of them can be displayed by passing the `--help` argument.

All options are optional: by default rspamd will try to read the `etc/rspamd.conf` config file and run as a daemon. Also there is a test mode that can be turned on by passing the `-t` argument. In test mode, rspamd reads the config file and checks its syntax. If a configuration file is OK, the exit code is zero. Test mode is useful for testing new config files without restarting rspamd.

## Managing rspamd using signals

It is important to note that all user signals should be sent to the rspamd main process and not to its children (as for child processes these signals can have other meanings). You can identify the main process:

- by reading the pidfile:

		$ cat pidfile

- by getting process info:

		$ ps auxwww | grep rspamd
		nobody 28378  0.0  0.2 49744  9424   rspamd: main process
		nobody 64082  0.0  0.2 50784  9520   rspamd: worker process
		nobody 64083  0.0  0.3 51792 11036   rspamd: worker process
		nobody 64084  0.0  2.7 158288 114200 rspamd: controller process
		nobody 64085  0.0  1.8 116304 75228  rspamd: fuzzy storage

		$ ps auxwww | grep rspamd | grep main
		nobody 28378  0.0  0.2 49744  9424   rspamd: main process

After getting the pid of the main process it is possible to manage rspamd with signals, as follows:

- `SIGHUP` - restart rspamd: reread config file, start new workers (as well as controller and other processes), stop accepting connections by old workers, reopen all log files. Note that old workers would be terminated after one minute which should allow processing of all pending requests. All new requests to rspamd will be processed by the newly started workers.
- `SIGTERM` - terminate rspamd.
- `SIGUSR1` - reopen log files (useful for log file rotation).

These signals may be used in rc-style scripts. Restarting of rspamd is performed softly: no connections are dropped and if a new config is incorrect then the old config is used.
