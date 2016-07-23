---
layout: doc_modules
title: Greylisting module
---

# Greylisting module

This module is intended to delay messages that have spam score above `greylisting` action threshold.

## Principles of work

Greylisting module saves 2 hashes for each message in Redis:

* **meta** hash is based on triplet `from`:`to`:`ip`
* **data** hash is taken from the message's body if it has enough length for it

IP address is stored with certain mask applied: it is `/19` for IPv4 and `/64` for IPv6 accordingly. Each hash has its own timestamp and Rspamd checks for the following times:

* `greylisting` time - when a message should be temporary rejected
* `expire` time - when a greylisting hash is stored in Redis

The hashes lifetime is depicted in the following scheme:

<img class="img-responsive" width="75%" src="/img/greylisting.png">

This module produces `soft reject` action on greylisting which **SHOULD** be treated as temporary rejection by MTA. Rmilter can recognize this action. Some other integrations cannot do it (for example, Exim integration), so this module won't work as expected.

## Module configuration

First of all, you need to setup Redis server for storing hashes. This procedure is described in details in the [following document](/doc/configuration/redis.html). Thereafter, you can modify couple of options specific for greylisting module. It is recommended to define these options in `local.d/greylisting.conf`:

* **`expire`**: setup hashes expire time (1 day by default)
* **`timeout`**: defines greylisting timeout (5 min by default)
* **`key_prefix`**: prefix for hashes to store in Redis (`rg` by default)
* **`max_data_len`**: maximum length of data to be used for body hash (10kb by default)
* **`message`**: a message for temporary rejection reason (`Try again later` by default)
* **`ipv4_mask`**: mask to apply for IPv4 addresses (19 by default)
* **`ipv6_mask`**: mask to apply for IPv6 addresses (64 by default)
