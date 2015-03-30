# Rspamd architecture

## Introduction

Rspamd is a universal spam filtering system based on event-driven processing 
model. It means that rspamd is intended not to block anywhere in the code. To
process messages rspamd uses a set of so called `rules`. Each `rule` is a symbolic
name associated with some message property. For example, we can define the following
rules:

- `SPF_ALLOW` - means that a message is validated by SPF;
- `BAYES_SPAM` - means that a message is statistically considered as spam;
- `FORGED_OUTLOOK_MID` - message ID seems to be forged for Outlook MUA.

Rules are defined by [modules](../modules/). So far, if there is a module that
performs SPF checks it may define several rules according to SPF policy:

- `SPF_ALLOW` - a sender is allowed to send messages for this domain;
- `SPF_DENY` - a sender is denied by SPF policy;
- `SPF_SOFTFAIL` - there is no affinity defined by SPF policy.

Rspamd supports two main types of modules: internal written in C and external
written in Lua. There is no real difference between these two types with the exception
that C modules are embeded all the time and can be enabled in `filters` attribute
in the `options` section of the config:

~~~nginx
options {
 filters = "regexp,surbl,spf,dkim,fuzzy_check,chartable,email";
 ...
}
~~~

## Protocol

Rspamd uses HTTP protocol for all operations. This protocol is described in the [protocol section](protocol.md).

## Metrics

Rules in rspamd, defines merely a logic of checks, however it is required to
set up weights for each rule. Weight means `significance` in terms of rspamd. So
far, rules with greater absolute value of weight are considered as more important
than the recent rules. The weight of rules is defined in `metrics`. Each metric
is a set of grouped rules with specific weights. For example, we may define the
following weights for our SPF rules:

- `SPF_ALLOW`: -1
- `SPF_DENY`: 2
- `SPF_SOFTFAIL`: 0.5

Positive weights means that this rule turns message to more spammy, while negative
means the opposite.

### Rules scheduler

To avoid unnecessary checks rspamd uses scheduler of rules for each message. So far,
if a message is considered as `definite spam` then further checks are not performed.
This scheduler is rather naive and it performs the following logic:

- select negative rules *before* positive ones to prevent false positives;
- prefer rules with the following characteristics:
  - frequent rules;
  - rules with more weight;
  - faster rules

These optimizations can filter definite spam more quickly than a generic queue.

Since rspamd-0.9 there are more optimizations for rules and expressions that are
roughly described in the [following presentation](http://highsecure.ru/ast-rspamd.pdf).

## Actions

Another important property of metrics is their actions set. This set defines recommended
actions for a message if it reach a certain score defined by all rules triggered.
Rspamd defines the following actions:

- `No action`: a message is likely ham;
- `Greylist`: greylist message is it is not certainly ham;
- `Add header`: a message is likely spam, so add a specific header;
- `Rewrite subject`: a message is likely spam, so rewrite its subject;
- `Reject`: a message is very likely spam, so reject it completely

These actions are just recommendations for MTA and are not to be strictly followed.
For all actions that are greater or equal than `greylist` it is recommended to
perform explicit greylisting. `Add header` and `rewrite subject` actions are very
close in semantics and are both considered as `probable spam`. `Reject` is a 
strong rule that usually means that a message should be really rejected by MTA.
The triggering score for these actions should be specified according to their logic
priorities. If two actions have the same weight, the result is unspecified.

## Rules weight

The weights of rules is not necessarily constant. For example, for statistics rules
we have no certain confidence if a message is spam or not. We have some probability
instead. To allow fuzzy rules weight, rspamd supports `dynamic weights`. Generally,
it means that a rule may add a dynamic range from 0 to a defined weight in the metric.
So far if we define symbol `BAYES_SPAM` with weight 5.0, then this rule can add
a resulting symbol with weight from 0 to 5.0. To distribute values in the proper
way, rspamd usually uses some sort of Sigma function to provide fair distribution curve.
Nevertheless, the most of rspamd rules uses static weights with the exception of
fuzzy rules.

## Statistic

Rspamd uses statistic algorithms to precise the final score of a message. Currently,
the only algorithm defined is OSB-Bayes. You may find the concrete details of this
algorithm in the following [paper](http://osbf-lua.luaforge.net/papers/osbf-eddc.pdf).
Rspamd uses window size of 5 words in its classification. During classification procedure,
rspamd split a message to a set of tokens. 

Tokens are separated by punctiation or space characters. Short tokens (less than 3 symbols) are ignored. For each token rspamd
calculates two non-cryptographic hashes used subsequently as indices. All these tokens
are stored in memory-mapped files called `statistic files` (or `statfiles`). Each statfile
is a set of token chains, indexed by the first hash. A new token may be inserted to some
chain, and if this chain is full then rspamd tries to expire less significant tokens to
insert a new one. It is possible to obtain the current state of tokens by running

	rspamc stat 

command that asks controller for free and used tokens in each statfile.
Please note that if a statfile is close to be completely filled then during subsequent
learning you will loose existing data. Therefore, it is recommended to increase size for
such statfiles.

## Running rspamd
 
There are several command-line options that can be passed to rspamd. All of them can be displayed by passing `--help` argument: 

All options are optional: by default rspamd would try to read `etc/rspamd.conf` config file and run as daemon. Also there is test mode that can be turned on by passing `-t` argument. In test mode, rspamd reads config file and checks its syntax. If a configuration file is OK, then exit code is zero. Test mode is useful for testing new config file withou rspamd restart. `--convert-config` option can be used to convert old style (pre 0.6.0) config to [ucl](../configuration/ucl.md) one: 

	$ rspamd -c ./rspamd.xml --convert-conf ./rspamd.conf

 
## Managing rspamd using signals

First of all, it is important to note that all user's signals should be sent to rspamd main process and not to its children (as for child processes these signals can have other meanings). To determine which process is main you can use two ways: 

- by reading pidfile: 

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

After getting the pid of main process it is possible to manage rspamd with signals:
 
- `SIGHUP` - restart rspamd: reread config file, start new workers (as well as controller and other processes), stop accepting connections by old workers, reopen all log files. Note that old workers would be terminated after one minute that should allow to process all pending requests. All new requests to rspamd will be processed by newly started workers. 
- `SIGTERM` - terminate rspamd system.
- `SIGUSR1` - reopen log files (useful for log files rotation). 

These signals may be used in start scripts as it is done in `FreeBSD` start script. Restarting of rspamd is performed softly: no connections are dropped and if a new config is incorrect then the old config is used. 