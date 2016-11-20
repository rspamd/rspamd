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
-   Quoted string (if string can have spaces or other special characters)
-   Numeric value
-   Flag (`yes`/`no` or `true`/`false`)
-   IP, network or hostname (eg. `127.0.0.1`, `192.168.1.0/24`, `[::1]/128`, `"example.com"`, `"example.com/24"`). Please note that hostnames must be enclosed in double quotes. If a hostname has multiple IP addresses they all will be added to the list.
-   Socket argument (eg. `host:port` or `/path/to/socket` or `fd:3` for systemd socket)
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

-   clamav - ClamAV definitions
-   spamd - Rspamd definitions
-   limits - limits definitions
-   greylisting - greylisting definitions

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
- `max_size`: maximum size of scanned message for ClamAV, Rspamd and DCC.
	+ Default: `0 (no limit)`
- `strict_auth`: strict checks for mails from authenticated senders (if it is `no` then messages originated from authenticated users and `our_networks` are **NOT** checked - that's a **default** value)
	+ Default: `no`
- `use_dcc`: flag that specify whether we should use DCC checks for mail
	+ Default: `no`
- `whitelist`: global recipients whitelist
	+ Default: `no`
- `our_networks`: treat mail from these networks as mail from authenticated users (list of ips or nets)
	+ Default: `empty`


## Clamav section

Specifies ClamAV antivirus scanners.

- `servers`: clamd socket definitions in format:
	1.  `/path/to/file`
	2.  `host[:port]`
	Sockets are separated by `,`
	+ Default: `empty`
- `connect_timeout`: timeout in milliseconds for connecting to clamd
	+ Default: `1s`
- `port_timeout`: timeout in milliseconds for waiting for clamd port response
	+ Default: `4s`
- `results_timeout`: timeout in milliseconds for waiting for clamd response
	+ Default: `20s`
- `error_time`: time in seconds during which we are counting errors
	+ Default: `10`
- `dead_time`: time in seconds during which we are thinking that server is down
	+ Default: `300`
- `maxerrors`: maximum number of errors that can occur during error_time to make Rmilter thinking that this upstream is dead
	+ Default: `10`
- `whitelist`: list of ips or nets that should be not checked with Rspamd
	+ Default: `empty`


## Spamd section

Specifies Rspamd scanners.

- `servers`: Rspamd socket definitions in format:
	1.  `/path/to/file`
	2.  `host[:port]`
- `connect_timeout`: timeout in milliseconds for connecting to rspamd
	+ Default: `1s`
- `results_timeout`: timeout in milliseconds for waiting for rspamd response
	+ Default: `20s`
- `error_time`: time in seconds during which we are counting errors
	+ Default: `10`
- `dead_time`: time in seconds during which we are thinking that server is down
	+ Default: `300`
- `maxerrors`: maximum number of errors that can occur during error_time to make Rmilter thinking that this upstream is dead
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
- `whitelist`: list of ips, nets or hostnames that should be not checked with Rspamd
	+ Default: `empty`
- `extended_spam_headers`: add extended Rspamd headers to messages **NOT** originated from authenticated users or `our_networks`, is useful for debugging or private mail servers (flag)
	+ Default: `false`
- `extended_headers_rcpt`: add extended Rspamd headers to messages if **EVERY** envelope recipient match this list (e.g. a list of domains mail server responsible for) (from 1.10.0, recipients list)
	+ Default: `empty`
- `spamd_never_reject`: never reject a message even if Rspamd action is `reject`, add header instead (flag)
	+ Default: `false`
- `spamd_temp_fail`: return temporary failure if spam servers could not be reached (ignore otherwise) (flag)
	+ Default: `false`
- `spamd_settings_id`: pass additional settings id for Rspamd (e.g. to distinguish inbound and outbound messages)
	+ Default: `empty`


## Redis section

Defines Redis servers for grey/whitelisting and ratelimits.

- `servers_grey`: Redis servers for greylisting in format: `host[:port][, host[:port]]`.
	+ Default: `empty`
- `servers_white`: Redis servers for whitelisting in format similar to that is used in *servers_grey*
	+ Default: `empty`
- `servers_limits`: Redis servers used for limits storing
	+ Default: `empty`
- `servers_id`: Redis servers used for storing messages IDs (used in replies checks)
	+ Default: `empty`
- `servers_spam`: Redis servers used to broadcast messages that are rejected as spam
    + Default: `empty`
- `servers_copy`: Redis servers used to broadcast copies of messages (amount is defined by `copy_probability`)
    + Default: `empty`
- `copy_probability`: a number that defines average amount of messages being copied to `servers_copy`, should be in range from 0.0 to 1.0 (e.g. 0.5 means that half of messages are copied in average)
    + Default: `1.0` - copy all if `servers_copy` is set
- `connect_timeout`: timeout in milliseconds for connecting to redis-server
	+ Default: `1s`
- `error_time`: time in seconds during which we are counting errors
	+ Default: `10`
- `dead_time`: time in seconds during which we are thinking that server is down
	+ Default: `300`
- `maxerrors`: maximum number of errors that can occur during error_time to make Rmilter thinking that this upstream is dead
	+ Default: `10`

It is also possible to set DB number and password for Redis:

- `dbname`: number of Redis database (see Redis [documentation](https://redis.io) for details), should be quoted string (e.g. `dbname = "3";`)
- `password`: password to access Redis, quoted string

Rmilter can also set custom prefixes for the keys pushed into Redis:

- `grey_prefix`: used for greylisting records
- `white_prefix`: used to whitelist records after greylisting
- `id_prefix`: used to store message ids

Copying messages to [Pub/Sub](http://redis.io/topics/pubsub) channels also requires to setup channels in Redis:

- `spam_channel`: channel for spam messages
- `copy_channel`: channel for copies


## Greylisting section

Greylisting related options.

- `timeout`: time during which we mark message greylisted
	+ Default: `300s`
- `expire`: time during which we save a greylisting record
	+ Default: `1d`
- `whitelist`: list of ip addresses or networks that should be whitelisted from greylisting
	+ Default: `empty`
- `enable`: enable or disable greylisting (from 1.9.1), binary flag
	+ Default: `true`


## Limits section

Rate limits are implemented as leaked bucket, so first value is
bucket burst - is peak value for messages in bucket (after reaching
it bucket is counted as overflowed and new messages are rejected),
second value is rate (how much messages can be removed from bucket
each second). It can be schematically displayed as following:

<div><img src="{{ site.url }}{{ site.baseurl }}/img/rspamd-schemes.006.jpg" alt="Leaking bucket" class="img-responsive" style="padding-bottom:20px; max-height: 200px;"></div>

- `limit_whitelist_ip`: don't check limits for specified ips, networks or hostnames
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
- `enable`: enable or disable rate limits (from 1.9.1), binary flag
	+ Default: `true`


## Dkim section

DKIM can be used to sign messages by. DKIM support must be
provided by OpenDKIM library.

- `header_canon`: canonization of headers (`simple` or `relaxed`)
    + Default: `simple`
- `body_canon`: canonization of body (`simple` or `relaxed`)
    + Default: `simple`
- `sign_alg`: signature algorithm (`sha1` and `sha256`)
    + Default: `sha1`
- `auth_only`: sign mail for authorized users only
    + Default: `yes`
- `domain`: domain entry must be enclosed in a separate section
    + `key` - path to private key
    + `domain` - domain to be used for signing (this matches with SMTP FROM data). If domain is `*` then Rmilter tries to search key in the `key` path as `keypath/domain.selector.key` for any domain.
    + `selector` - dkim DNS selector (e.g. for selector *dkim* and domain *example.com* DNS TXT record should be for `dkim._domainkey.example.com`).
- `sign_networks` - specify internal networks to perform signing as well (hostnames could also be used)
    + Default: `empty`
- `enable`: enable or disable DKIM signing (from 1.9.2), binary flag
    + Default: `true`
- `rspamd_sign`: use rspamd signing instead of the own logic (from 1.10.0)
    + Default: `false`

## The order of checks

1. DKIM test from and create signing context (MAIL FROM)
2. Ratelimit (RCPT TO)
3. Greylisting (DATA) if Rspamd greylisting is disabled
4. Ratelimit (EOM, set bucket value)
5. Message size (EOM) if failed, skip ClamAV, DCC and Rspamd checks
6. Rspamd (EOM)
7. ClamAV (EOM)
8. DKIM add signature (EOM)

## Keys used in Redis

-   *rcpt* - bucket for rcpt filter
-   *rcpt:ip* - bucket for rcpt_ip filter
-   *rcpt:ip:from* - bucket for rcpt_ip_from filter
-   *rcpt:* - bucket for bounce_rcpt filter
-   *rcpt:ip:* - bucket for bounce_rcpt_ip filter
-   *hash(from . ip . to)* - key for greylisting triplet (hexed string of hash value)
