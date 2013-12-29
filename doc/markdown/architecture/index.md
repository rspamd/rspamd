# Rspamd architecture

## Introduction

Rspamd is a universal spam filtering system based on event-driven processing 
model. It means that rspamd is intented not to block anywhere in the code. To
process messages rspamd uses a set of so called `rules`. Each `rule` is a symbolic
name associated with some message property. For example, we can define the following
rules:

- SPF_ALLOW - means that a message is validated by SPF;
- BAYES_SPAM - means that a message is statistically considered as spam;
- FORGED_OUTLOOK_MID - message ID seems to be forged for Outlook MUA.

Rules are defined by [modules](../modules/). So far, if there is a module that
performs SPF checks it may define several rules accroding to SPF policy:

- SPF_ALLOW - a sender is allowed to send messages for this domain;
- SPF_DENY - a sender is denied by SPF policy;
- SPF_SOFTFAIL - there is no affinity defined by SPF policy.

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

## Metrics

Rules in rspamd, defines merely a logic of checks, however it is required to
set up weights for each rule. Weight means `significance` in terms of rspamd. So
far, rules with greater absolute value of weight are considered as more important
than the recent rules. The weight of rules is defined in `metrics`. Each metric
is a set of grouped rules with specific weights. For example, we may define the
following weights for our SPF rules:

- SPF_ALLOW: -1
- SPF_DENY: 2
- SPF_SOFTFAIL: 0.5

Positive weights means that this rule turns message to more spammy, while negative
means the opposite.

### Rules scheduler

To avoid unnecessary checks rspamd uses scheduler of rules for each message. This
scheduler is rather naive and it performs the following logic:

- select negative rules *before* positive ones to prevent false positives;
- prefer rules with the following characteristics:
  - frequent rules;
  - rules with more weight;
  - faster rules

These optimizations can filter definite spam more quickly than a generic queue.

## Actions

Another important property of metrics is their actions set. This set defines recommended
actions for a message if it reach a certain score defined by all rules triggered.
Rspamd defines the following actions:

- **No action**: a message is likely ham;
- **Greylist**: greylist message is it is not certainly ham;
- **Add header**: a message is likely spam, so add a specific header;
- **Rewrite subject**: a message is likely spam, so rewrite its subject;
- **Reject**: a message is very likely spam, so reject it completely

These actions are just recommendations for MTA and are not to be strictly followed.
For all actions that are greater or equal than *greylist* it is recommended to
perform explicit greylisting. *Add header* and *rewrite subject* actions are very
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
