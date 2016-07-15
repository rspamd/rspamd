---
layout: rmilter
title: Rmilter configuration
---

# Rmilter configuration

This document describes Rmilter configuration options.

## Configuration format

The configuration file has format:

    name = value ;

Value may be:

-   String (may not contain spaces)
-   Quoted string (if string may contain spaces)
-   Numeric value
-   Flag (`yes`/`no` or `true`/`false`)
-   IP or network (eg. `127.0.0.1`, `192.168.1.0/24`, `[::1]/128`)
-   Socket argument (eg. `host:port` or `/path/to/socket` or `fd:3` for systemd socket)
-   Regexp (eg. `/Match\*/`)
-   List (eg. `value1, value2, value3`)
-   Recipients list (`user, user@domain, @domain`)
-   Time argument (eg. `10s`, `5d`)

Some directives MUST be specified only in specified sections. Section
definition looks like:

     section_name {
             section_directive;
             ...
     }

## Common sections

-   clamav - clamav definitions
-   spamd - Rspamd definitions
-   limits - limits definitions
-   greylisting - greylisting definitions
-   rule - regexp rule definition (a section per rule)

Directives that can be defined in configuration file:

## Global section

Defines global options.

- `pidfile`: specify path to pidfile
	+ Default: `/var/run/rmilter.pid`
- `tempdir`: specify path to temporary directory. For maximum performance, it is recommended to put it on memory file system.
	+ Default: `$TMPDIR`
- `bind_socket`: socket credits for local bind:
	+ Default: `bind_socket = unix:/var/tmp/rmilter.sock`
	1.  `unix:/path/to/file` - bind to local socket
	2.  `inet:[port@host]` - bind to inet socket
- `max_size`: maximum size of scanned message for clamav, spamd and dcc.
	+ Default: `0 (no limit)`
- `strict_auth`: strict checks for mails from authenticated senders (if it is `no` then messages for authenticated users are **NOT** checked - that's a **default** value)
	+ Default: `no`
- `use_dcc`: flag that specify whether we should use dcc checks for mail
	+ Default: `no`
- `whitelist`: global recipients whitelist
	+ Default: `no`
- `our_networks`: treat mail from these networks as mail from authenticated users (see also `strict_auth`)
	+ Default: `empty`

Back to [top](#).

## Clamav section

Specifies clamav antivirus scanners.

- `servers`: clamav socket definitions in format:
	1.  `/path/to/file`
	2.  `host[:port]`
	Sockets are separated by `,`
	+ Default: `empty`
- `connect_timeout`: timeout in miliseconds for connecting to clamav
	+ Default: `1s`
- `port_timeout`: timeout in miliseconds for waiting for clamav port response
	+ Default: `4s`
- `results_timeout`: timeout in miliseconds for waiting for clamav response
	+ Default: `20s`
- `error_time`: time in seconds during which we are counting errors
	+ Default: `10`
- `dead_time`: time in seconds during which we are thinking that server is down
	+ Default: `300`
- `maxerrors`: maximum number of errors that can occur during error_time to make rmilter thinking that this upstream is dead
	+ Default: `10`
- `whitelist`: list of ips or nets that should be not checked with spamd
	+ Default: `empty`

Back to [top](#).

## Spamd section

Specifies Rspamd scanners.

- `servers`: Rspamd socket definitions in format:
	1.  `/path/to/file`
	2.  `host[:port]`
- `connect_timeout`: timeout in milliseconds for connecting to spamd
	+ Default: `1s`
- `results_timeout`: timeout in milliseconds for waiting for spamd response
	+ Default: `20s`
- `error_time`: time in seconds during which we are counting errors
	+ Default: `10`
- `dead_time`: time in seconds during which we are thinking that server is down
	+ Default: `300`
- `maxerrors`: maximum number of errors that can occur during error_time to make rmilter thinking that this upstream is dead
	+ Default: `10`
- `reject_message`: reject message for spam (quoted string)
	+ Default: `Spam message rejected; If this is not spam contact abuse team`
- `spamd_soft_fail`: if action is not reject use it for other actions (flag)
	+ Default: `true`
- `spamd_greylist`: greylist message only if action is greylist (flag)
	+ Default: `true`
- `spam_header`: add specified header if action is add_header and spamd_soft_fail os turned on
	+ Default: `X-Spam`
- `rspamd_metric`: Rspamd metric that would define whether we reject message as spam or not (quoted string)
	+ Default: `default`
- `whitelist`: list of ips or nets that should be not checked with spamd
	+ Default: `empty`
- `extended_spam_headers`: add extended spamd headers to messages, is useful for debugging or private mail servers (flag)
	+ Default: `false`
- `spamd_never_reject`: never reject a message even if spamd action is `reject`, add header instead (flag)
	+ Default: `false`
- `spamd_temp_fail`: return temporary failure if spam servers could not be reached (ignore otherwise) (flag)
	+ Default: `false`
- `spamd_settings_id`: pass additional settings id for Rspamd (e.g. to distinguish inbound and outbound messages)
  + Default: `empty`

Back to [top](#).

## Redis section

Defines redis servers for grey/whitelisting and ratelimits.

- `servers_grey`: redis servers for greylisting in format: `host[:port][, host[:port]]`.
	+ Default: `empty`
- `servers_white`: redis servers for whitelisting in format similar to that is used in *servers_grey*
	+ Default: `empty`
- `servers_limits`: redis servers used for limits storing
	+ Default: `empty`
- `servers_id`: redis servers used for storing messages IDs (used in replies checks)
	+ Default: `empty`
- `servers_spam`: redis servers used to broadcast messages that are rejected as spam
    + Default: `empty`
- `servers_copy`: redis servers used to broadcast copies of messages (amount is defined by `copy_probability`)
    + Default: `empty`
- `copy_probability`: a number that defines average amount of messages being copied to `servers_copy`, should be in range from 0.0 to 1.0 (e.g. 0.5 means that half of messages are copied in average)
    + Default: `1.0` - copy all if `servers_copy` is set
- `connect_timeout`: timeout in miliseconds for connecting to redis
	+ Default: `1s`
- `error_time`: time in seconds during which we are counting errors
	+ Default: `10`
- `dead_time`: time in seconds during which we are thinking that server is down
	+ Default: `300`
- `maxerrors`: maximum number of errors that can occur during error_time to make rmilter thinking that this upstream is dead
	+ Default: `10`

It is also possible to set DB number and password for Redis:

- `dbname`: number of Redis database (see Redis [documentation](https://redis.io) for details)
- `password`: password to access Redis

Rmilter can also set custom prefixes for the keys pushed into Redis:

- `grey_prefix`: used for greylisting records
- `white_prefix`: used to whitelist records after greylisting
- `id_prefix`: used to store message ids

Copying messages to [pub/sub](http://redis.io/topics/pubsub) channels also requires to setup channels in Redis:

- `spam_channel`: channel for spam messages
- `copy_channel`: channel for copies

Back to [top](#).

## Greylisting section

Greylisting related options.

- `timeout (required)`: time during which we mark message greylisted
	+ Default: `300s`
- `expire (required)`: time during which we save a greylisting record
	+ Default: `empty (greylisting disabled)`
- `whitelist`: list of ip addresses or networks that should be whitelisted from greylisting
	+ Default: `empty`

Back to [top](#).

## Limits section

Rate limits are implemented as leaked bucket, so first value is
bucket burst - is peak value for messages in bucket (after reaching
it bucket is counted as overflowed and new messages are rejected),
second value is rate (how much messages can be removed from bucket
each second). It can be schematically displayed as following:

![Leaked bucket scheme](https://rspamd.com/img/rspamd-schemes.006.jpg "Leaking bucket")

- `limit_whitelist_ip`: don't check limits for specified ips
	+ Default: `empty`
- `limit_whitelist_rcpt`: don't check limits for specified recipients
	+ Default: `no`
- `limit_bounce_addrs`: list of address that require more strict limits
	+ Default: `postmaster, mailer-daemon, symantec_antivirus_for_smtp_gateways, null, fetchmail-daemon`
- `limit_bounce_to`: limits bucket for bounce messages (only rcpt to)
	+ Default: `5:0.000277778`
- `limit_bounce_to_ip`: limits bucket for bounce messages (only rcpt to per one source ip)
	+ Default: `5:0.000277778`
- `limit_to`: limits bucket for non-bounce messages (only rcpt to)
	+ Default: `20:0.016666667`
- `limit_to_ip`: limits bucket for non-bounce messages (only rcpt to per one source ip)
	+ Default: `30:0.025`
- `limit_to_ip_from`: limits bucket for non-bounce messages (msg from, rcpt to per one source ip)
	+ Default: `100:0.033333333`

Back to [top](#).

## DKIM section

Dkim can be used to sign messages by. Dkim support must be
provided by opendkim library.

- `header_canon`: canonization of headers (simple or relaxed)
    + Default: `simple`
- `body_canon`: canonization of body (simple or relaxed)
    + Default: `simple`
- `sign_alg`: signature algorithm (`sha1` and `sha256`)
    + Default: `sha1`
- `auth_only`: sign mail for authorized users only
    + Default: `yes`
- `domain`: domain entry must be enclosed in a separate section
    +   `key` - path to private key
    +   `domain` - domain to be used for signing (this matches with SMTP FROM data). If domain is `*` then rmilter tries to search key in the `key` path as `keypath/domain.selector.key` for any domain.
    +   `selector` - dkim DNS selector (e.g. for selector *dkim* and domain *example.com* DNS TXT record should be for `dkim._domainkey.example.com`).
- `sign_networks` - specify internal network to perform signing as well
	+ Default: `empty`

Back to [top](#).

## The order of checks

1.  DKIM test from and create signing context (MAIL FROM)
2.  Ratelimit (RCPT TO)
3.  Greylisting (DATA)
4.  Ratelimit (EOM, set bucket value)
5.  Rules (EOM)
6.  SPF (EOM)
7.  Message size (EOM) if failed, skip clamav, dcc and spamd checks
8.  DCC (EOM)
10. Rspamd (EOM)
9.  Clamav (EOM)
12. DKIM add signature (EOM)

Back to [top](#).

## Keys used in redis

-   *rcpt* - bucket for rcpt filter
-   *rcpt:ip* - bucket for rcpt_ip filter
-   *rcpt:ip:from* - bucket for rcpt_ip_from filter
-   *rcpt:* - bucket for bounce_rcpt filter
-   *rcpt:ip:* - bucket for bounce_rcpt_ip filter
-   *hash(from . ip . to)* - key for greylisting triplet (hexed string of hash value)

Back to [top](#).