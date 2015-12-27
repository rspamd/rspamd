---
layout: doc_quickstart
title: Rspamd quick start
---

# Rspamd quick start

This guide describes the main procedures to get and start working with rspamd.

## Rspamd installation

Please check the corresponding [downloads page](/downloads.html) that describes how to obtain rspamd, how to install it and, alternatively, how to build it from the sources.

## Running Rspamd

### Platforms with systemd (Arch, CentOS 7, Debian Jessie, Fedora, openSUSE, SLE)

To enable run on startup:

	systemctl enable rspamd.socket

To start once:

	systemctl start rspamd.socket

Rspamd will be started on-demand, so to simulate this you could run:

	rspamc stat

### Ubuntu, Debian Wheezy

To enable run on startup:
	
	update-rc.d rspamd defaults

To start once:
	
	/etc/init.d/rspamd start

### CentOS 6

To enable run on startup:

	chkconfig rspamd on

To start once:

	/etc/init.d/rspamd start

For information about how to configure different MTA with rspamd, please consider the [following document](https://rspamd.com/doc/integration.html).

## Configuring Rspamd

Though Rspamd's default config aims to be useful for most purposes you may wish to make some adjustments to it to suit your environment/tastes.

There are some different approaches you could take to this which suffer similar drawbacks:

1) Is to modify the stock config files in `/etc/rspamd` directly. Your package manager will not replace the modified config files on upgrade- and may prompt you to merge changes or install these files with an added extension depending on your platform.

2) Is to instead create an `rspamd.conf.local` and/or `rspamd.conf.local.override` in the `/etc/rspamd` directory. What distinguishes these files is the way in which they alter config- `rspamd.conf.local` adds or _merges_ config elements (and is useful for example for setting custom metrics) while `rspamd.conf.local.override` adds or _replaces_ config elements (and is useful for example for configuring workers or RBLs).

### Setting listening interface

Rspamd's normal worker will by default listen on all interfaces on port 11333. If you're running Rspamd on the same machine as your mailer (or whatever will be querying it) you might want to set this to 'localhost' instead.

This is configured in `rspamd.conf` or `rspamd.sysvinit.conf` on Debian Wheezy & Ubuntu. The config to be modified is shown below (`*` should be replaced with whatever address you would prefer to listen on).

    worker {
        bind_socket = "*:11333";
        .include "$CONFDIR/worker-normal.inc"
    }

If you plan to leave this as is you may wish to use a firewall to restrict access to your own machines.

### Setting controller password

Rspamd requires a password when queried from non-trusted IPs except for scanning messages which is unrestricted (the default config trusts the loopback interface). This is configured in `worker-controller.inc`. The config to be modified is shown below (replace 'q1' with your chosen password):

`password = "q1";`

Optionally you may set `enable_password` - if set, data-changing operations (such as training bayes or fuzzy storage) will require this password. For example:

`enable_password = "q2";`

Moreover, you can store encrypted password for better security. To generate such a password just type

	$ rspamd --encrypt-password
	Enter passphrase:
	$1$4mqeynj3st9pb7cgbj6uoyhnyu3cp8d3$59y6xa4mrihaqdw3tf5mtpzg4k7u69ypebc3yba8jdssoh39x16y

Then you can copy this string and store it in the configuration file. Rspamd uses [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) algorithm that makes it very hard to brute-force this password even if it has been compromised.

### Pre-built statistics

Rspamd is shipped with [pre-built statistics](https://rspamd.com/rspamd_statistics/). Since version 1.0 release, we would recommend to bootstrap your `BAYES` statistics using sqlite3. To load the pre-built statistics, please ensure, that your 
`${CONFDIR}/statistics.conf` contains the following setting:


	classifier {
		type = "bayes";
		tokenizer {
			name = "osb";
		}
		cache {
			path = "${DBDIR}/learn_cache.sqlite";
		}
		min_tokens = 11;
		backend = "sqlite3";
		languages_enabled = true;
		statfile {
			symbol = "BAYES_HAM";
			path = "${DBDIR}/bayes.ham.sqlite";
			spam = false;
		}
		statfile {
			symbol = "BAYES_SPAM";
			path = "${DBDIR}/bayes.spam.sqlite";
			spam = true;
		}
	}

Then you can download two files using the following commands:

	wget -O /var/lib/rspamd/bayes.spam.sqlite http://rspamd.com/rspamd_statistics/bayes.spam.sqlite
	wget -O /var/lib/rspamd/bayes.ham.sqlite http://rspamd.com/rspamd_statistics/bayes.ham.sqlite

For some systems, namely old centos (6 or 7) the shipped sqlite version won't be able to use pre-shipped statfiles. For that purposes, there are also the raw sql dumps for statfiles which could
be used in the following way:
	
	wget http://rspamd.com/rspamd_statistics/bayes.spam.sql.xz
	wget http://rspamd.com/rspamd_statistics/bayes.ham.sql.xz
	xz -cd bayes.spam.sql.xz | sqlite3 /var/lib/rspamd/bayes.spam.sqlite
	xz -cd bayes.ham.sql.xz | sqlite3 /var/lib/rspamd/bayes.ham.sqlite

Don't forget to change ownership to allow rspamd user (usually `_rspamd`) to learn further messages into these statistics:

	chown _rspamd:_rspamd /var/lib/rspamd/bayes.*.sqlite

Afterwards, you would have pre-learned statistics for several languages.

### Configuring RBLs

Though Rspamd is free to use for any purpose many of the RBLs used in the default configuration aren't & care should be taken to see that your use cases are not infringing. Notes about specific RBLs follow below (please follow the links for details):

[Spamhaus](https://www.spamhaus.org/organization/dnsblusage/) - Commercial use forbidden (see link for definition); Limit of 300k queries or 100k SMTP connections per day

[URIBL](http://uribl.com/about.shtml) - Requires a commercial subscription if 'excessive queries' are sent (numbers unclear).

[SURBL](http://www.surbl.org/usage-policy) - Commercial use forbidden (see link for definition); Limit of 1k users or 250k queries per day

[DNSWL](https://www.dnswl.org/?page_id=9) - Commercial use forbidden (see link for definition); Limit of 100k queries per day

[SpamEatingMonkey](http://spameatingmonkey.com/faq.html#query-limits) - Limit of 100k queries per day or more than 5 queries per second for more than a few minutes

[SORBS](http://www.sorbs.net/general/using.shtml#largesites) - Limit of 100k users or more than 5 messages per second sustained

[Mailspike](http://mailspike.net/usage.html) - Limit of 100k messages or queries per day

[UCEProtect](http://www.uceprotect.net/en/index.php?m=6&s=11) - If you're sending 100k queries or more per day you should use the (free) Rsync service.

These are configured in `modules.conf` in the `rbl{}` and `surbl{}` sections. Detailed documentation for the RBL module is available [here](https://rspamd.com/doc/modules/rbl.html).

## Using Rspamd

### Using rspamc

`rspamc` implements a feature-complete client for Rspamd. For detailed documentation refer to `man rspamc`.

Common use-cases for `rspamc` include:

* Scanning messages stored on disk
* Training bayesian classifier
* Administering fuzzy storage
* Acting as a local delivery agent

### Using the WebUI

Rspamd has a built-in WebUI supporting setting metric actions & scores; training bayes & scanning messages- for more information see the [webui documentation](https://rspamd.com/webui).

### MTA integration

Usually you will want to integrate rspamd with your MTA- see the [integration guide](https://rspamd.com/doc/integration.html) for details.

### Custom integration

Rspamd speaks plain HTTP and can be easily integrated with your own apps- refer to the [protocol description](https://rspamd.com/doc/architecture/protocol.html) for details.
