---
layout: doc_conf
title: Upstreams configuration
---

# Upstreams configuration in Rspamd

This document describes **upstreams**: list of servers that are selected by Rspamd using specific algorithm to establish a connection.

## Introduction

List of upstreams is a common structure used in various Rspamd configuration options when you need to setup some remote servers. For example, upstreams are used to connect to a Redis server, to select a DNS server and to establish a connection by Rspamd proxy. Servers in upstream list can be defined by IP addresses (IPv6 addresses should be enclosed in brackets):

    127.0.0.1,[::1]

by names:

    serv1.example.com,serv2.example.com

You can also specify custom ports if they differ from the default ones (e.g. `53` for DNS):

    serv1.example.com:8080,serv2.example.com

It is also possible to define upstreams priorities (described later), but in this case you must also specify a port number:

    127.0.0.1:53:10,8.8.8.8:53:1

Upstreams line can be separated by commas or by semicolons in any combination. You can prepend rotation algorithm to the upstreams line to override the default rotation method (specific for each upstream list definition):

    master-slave:127.0.0.1:53:10,8.8.8.8:53:1

There are several algorithms available in Rspamd so far:

* `master-slave`
* `round-robin`
* `random`
* `sequential`
* `hash`

### Master-slave algorithm

This algorithm always select the upstream with highest weight unless it is not alive. For example, `master-slave:127.0.0.1:53:10,8.8.8.8:53:1`, line specifies that `127.0.0.1` will be always used if possible. You can skip priorities, then the first element is treated as master and the subsequent ones are used as slaves: `master-slave:127.0.0.1,8.8.8.8` is the equialent of the previous definition.

### Round-robin algorithm

In this algorithm, upstreams are selected based on its weight, but, after selection, the upstream's weight is decreased by one. For example, `round-robin:127.0.0.1:53:10,8.8.8.8:53:1` will select `127.0.0.1` 10 times and `8.8.8.8` merely one time. After all upstreams are rotated, Rspamd reset current weights to the initial ones. Hence, this could be treated as `10:1` distribution for these two upstreams. Upstreams with errors pending have their priorities penalised according to number of errors pending, so Rspamd prefers to select upstreams with no errors.

### Sequential algorithm

Selects upstreams sequentially ignoring priorities.

### Random algorithm

Selects upstreams randomly ignoring priorities.

### Hash algorithm

Selects upstream based on hash value of the input key. Rspamd uses a [consistent hash algorithm](http://arxiv.org/abs/1406.2294) that allows you to split data between shards based on some key value. This rotation is available for specific upstreams, for example, some Redis upstreams. Otherwise, `round-robin` algorithm is used.

## Upstreams lifetime

Each upstream is monitored by Rspamd for errors. If an error occur Rspamd places an upstream in monitoring mode during which it analyses errors rate (this is usually set by options `max_errors` and `error_time` where rate is calculated by `errors` / `time elapsed since monitoring start`). If this error rate is higher than desired (`max_errors` / `error_time`) then Rspamd marks upstream as inactive unless there are no active upstreams. Any successful connection during `monitoring` state returns an upstream to the `active` state. Upon reaching error rate limit, an upstream is marked as inactive and Rspamd waits for some time configured by option `dead_time` to restore upstream in the active list. The overall process is depicted in the following scheme:

<img class="img-responsive" width="75%" src="{{ site.baseurl }}/img/upstreams.png">

## Name resolution

Rspamd has a special treatment for upstreams defined with their names. During `dead_time`, Rspamd tries to re-resolve names and insert new IP addresses into upstream. If a name has multiple addresses, then Rspamd inserts all. Addresses are selected using round-robin rotation with error checking. Unlike upstreams configurations, errors are persistent and not cleared after successful attempts, so Rspamd always select an address with fewer errors count. This is done to turn off an IPv6 address, for example, if IPv6 is improperly configured in the system.
