---
layout: doc_quickstart
title: Quick start
---

<div><h1 style="margin-top:0">Rspamd and Rmilter quick start</h1></div>

## Introduction

This guide describes the main steps to get and start working with Rspamd. In particular, we describe the following setup:

- Debian Jessie (or another OS with systemd)
- Postfix MTA
- Rmilter
- Redis cache
- Dovecot with Sieve plugin to sort mail and learn by moving messages to `Junk` folder

For those who are planning migration from SpamAssassin, it might be useful to check the [SA migration guide]({{ site.baseurl }}/doc/tutorials/migrate_sa.html)

## Preparation steps

First of all, you need a working <abbr title="Mail Transfer Agent">MTA</abbr> that can send and receive email for your domain using <abbr title="Simple Mail Transfer Protocol">SMTP</abbr> protocol. In this guide, we describe the setup of the [Postfix MTA](http://www.postfix.org/). However, Rspamd can work with other MTA software - you can find details in the [integration document]({{ site.baseurl }}/doc/integration.html).

### TLS Setup

It is strongly recommended to setup TLS for your mail system. We suggest to use certificates issued by [Let’s&nbsp; Encrypt](https://letsencrypt.org) as they are free to use and are convenient to manage. To get such a certificate for your domain you need to allow Let’s&nbsp;Encrypt to check your domain. There are many tools available for these purposes, including the official client and couple of alternative clients, for example [acmetool](https://github.com/hlandau/acme). The setup is fairly simple: just type

    apt-get install acmetool
    acmetool quickstart
    acmetool want mail.example.com

In this guide, we assume that all services have the same certificate which might not be desired if you want greater levels of security.

### Postfix setup

We assume that you are installing Postfix with your OS's package manager (e.g. `apt-get install postfix`). Here is the desired configuration for Postfix:

<div><!-- Do not change the DOM structure -->
    <a class="btn btn-info btn-block btn-code" data-toggle="collapse" data-target="#main_cf">
        <i class="fa fa-caret-square-o-down fa-pull-right"></i>
        main.cf
    </a>
<div id="main_cf" class="collapse collapse-block">
<pre><code>
# SSL setup (we assume the same certs for IMAP and SMTP here)
smtpd_tls_cert_file = /var/lib/acme/live/mail.example.com/fullchain
smtpd_tls_key_file = /var/lib/acme/live/mail.example.com/privkey
smtpd_use_tls = yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
#smtp_tls_security_level = dane # Works only with the recent postfix
#smtp_dns_support_level = dnssec
smtpd_tls_ciphers = high
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3
smtp_tls_mandatory_ciphers = high
smtp_tls_mandatory_exclude_ciphers = RC4, MD5, DES
smtp_tls_exclude_ciphers = aNULL, RC4, MD5, DES, 3DES
# Change this for your domain
myhostname = mail.example.com
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
virtual_alias_maps = hash:/etc/postfix/virtual
myorigin = /etc/mailname
mydestination = example.com, localhost, localhost.localdomain, localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 10.0.0.0/8
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
home_mailbox = Maildir/
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth # Need to be enabled for Dovecot as well
smtpd_sasl_authenticated_header = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $myhostname
broken_sasl_auth_clients = yes
smtpd_sender_restrictions = reject_unknown_sender_domain
mailbox_command = /usr/lib/dovecot/deliver -c /etc/dovecot/dovecot.conf -m "${EXTENSION}"
smtpd_tls_received_header = yes
smtpd_tls_auth_only = yes
tls_random_source = dev:/dev/urandom
message_size_limit = 52428800

# Setup basic SMTP attrs
smtpd_soft_error_limit = 2
smtpd_error_sleep_time = ${stress?0}${stress:10s}
smtpd_hard_error_limit = ${stress?3}${stress:20}
smtpd_recipient_limit = 100
smtpd_timeout = ${stress?30}${stress:300}
smtpd_delay_reject = no
smtpd_helo_required = yes
strict_rfc821_envelopes = yes
# Greeting delay of 7 seconds
smtpd_client_restrictions =
        check_client_access hash:/etc/postfix/access,
        permit_mynetworks,
        sleep 7,
        reject_unauth_pipelining,

smtpd_recipient_restrictions = reject_unknown_sender_domain, reject_unknown_recipient_domain, reject_unauth_pipelining, permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
smtpd_data_restrictions =
        permit_sasl_authenticated,
        permit_mynetworks,
        reject_unauth_pipelining,

smtpd_end_of_data_restrictions =
        permit_sasl_authenticated,
        permit_mynetworks,
smtpd_relay_restrictions = check_recipient_access hash:/etc/postfix/access, reject_non_fqdn_sender, reject_unknown_sender_domain, permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination, reject_non_fqdn_helo_hostname, reject_invalid_helo_hostname,

# Rmilter setup
smtpd_milters = inet:localhost:9900
milter_default_action = accept
milter_protocol = 6
milter_mail_macros = i {mail_addr} {client_addr} {client_name} {auth_authen}
</code></pre>
</div></div>

You also need to create maps for access control and virtual aliases:

    touch /etc/postfix/virtual
    touch /etc/postfix/access
    postmap hash:/etc/postfix/virtual
    postmap hash:/etc/postfix/access

### Dovecot setup

For <abbr title="Internet Mail Access Protocol">IMAP</abbr> we recommend to install Dovecot. For Debian based systems you can use the following packages:

	apt-get install dovecot-imapd dovecot-sieve

Configuration of Dovecot (especially its authentication mechanisms) is a bit out of the scope for this guide but you can find many good guides at the [Dovecot main site](http://dovecot.org). By default, Dovecot uses Unix users in system and place mail into the standard mailbox `/var/mail/username`.

However, you should setup Postfix authentication. This lives in `/etc/dovecot/conf.d/10-master.conf`: make sure that you have uncommented the following lines in this file:

~~~
  # Postfix smtp-auth
  unix_listener /var/spool/postfix/private/auth {
    mode = 0666
  }
~~~

Furthermore, it might be useful to setup TLS to avoid passwords and other sensible information to be passed throughout insecure connections.

~~~
# /etc/dovecot/conf.d/10-ssl.conf

ssl = required
ssl_cert = </var/lib/acme/live/mail.example.com/fullchain
ssl_key = </var/lib/acme/live/mail.example.com/privkey
~~~

## Caching setup

Both Rspamd and Rmilter can use [Redis](https://redis.io) for caching. Rmilter uses Redis for the following features:

- greylisting (delaying of suspicious emails)
- rate limits
- storing reply message IDs to avoid certain checks for replies to our own messages

Rspamd uses Redis as well:

- for statistic tokens (BAYES classifier)
- for storing learned messages IDs
- for storing DMARC stats (optionally)

Installation of Redis is quite straightforward: install it using packages, start it with the default settings (it should listen on local interface using port 6379) and you are done. You might also want to limit memory used by Redis at some sane value:

    maxmemory 500mb

Note that for the moment by default stable releases of Redis listen for connections from all network interfaces. This is potentially dangerous and in most cases should be limited to the loopback interfaces, with the following configuration directive:

	bind 127.0.0.1 ::1

## Rmilter setup

When you are done with Postfix/Dovecot/Redis initial setup, it might be a good idea to setup Rmilter. Rmilter is used to connect Postfix (or Sendmail) with Rspamd. It can alter messages, change subject, reject spam, perform greylisting, check rate limits and even sign messages for authorized users/networks with DKIM signatures.

To install Rmilter, please follow the instructions on the [downloads page]({{ site.baseurl }}/downloads.html) but install `rmilter` package instead of `rspamd`. With the default configuration, Rmilter will use Redis and Rspamd on the local machine. You might want to change the bind settings as the default settings the use of unix sockets which might not work in some circumstances. To use TCP sockets for Rmilter, you can set the `bind_socket` option according to your Postfix setup:

	bind_socket = inet:9900@127.0.0.1;

For advanced setup, please check the [Rmilter documentation]({{ site.baseurl }}/rmilter/). Rmilter starts as daemon (e.g. by typing `service rmilter start`) and writes output to the system log. If you have a systemd-less system, then you can check Rmilter logs in the `/var/log/mail.log` file. For systemd, please check your OS documentation about reading logs as the exact command might differ from system to system.

## Rspamd installation

The download process is described in the [downloads page]({{ site.baseurl }}/downloads.html) where you can find how to get Rspamd, how to install it in your system, and, alternatively, how to build Rspamd from the sources.

## Running Rspamd

### Platforms with systemd (Arch, CentOS 7, Debian Jessie, Fedora, Ubuntu Xenial)

Packaging should start rspamd and configure it to run on startup on installation.

You can verify it's running as follows:

```
systemctl status rspamd
```

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

## Configuring Rspamd

Though Rspamd's default config aims to be useful for most purposes you may wish to make some adjustments to suit your environment/tastes.

There are some different approaches you can take to this:

1. **Not recommended**: Modify the stock config files in `/etc/rspamd` directly. Your package manager will not replace the modified config files on upgrade - and may prompt you to merge changes or install these files with an added extension depending on your platform.

2. Create, instead, an `rspamd.conf.local` and/or `rspamd.conf.override` in the `/etc/rspamd` directory. What distinguishes these files is the way in which they alter the configuration - `rspamd.conf.local` adds or _merges_ config elements (and is useful, for example, for setting custom metrics) while `rspamd.conf.override` adds or _replaces_ config elements (and is useful for redefining configuration completely)

3. For each individual configuration file shipped with Rspamd, there are two special includes (available from **Rspamd version 1.2 onwards**):

~~~ucl
.include(try=true,priority=1) "$CONFDIR/local.d/config.conf"
.include(try=true,priority=10) "$CONFDIR/override.d/config.conf"
~~~

Therefore, you can either extend (using local.d) or ultimately override (using override.d) any settings in the configuration. Unlike `rspamd.conf.local` and `rspamd.conf.override`, `local.d` and `override.d` operate inside a given block of configuration (`{}`).

For example, let's change some default symbols shipped with Rspamd. To do that we can create and edit `etc/rspamd/local.d/metrics.conf`:

~~~ucl
# /etc/rspamd/override.d/metrics.conf
symbol "BLAH" {
    score = 20.0;
}

group "Some group" {
    symbol "FOO" {
        score = 20.0;
    }
}
~~~

We can also use an override file. For example, let's redefine actions and set a more restrictive `reject` score. To do this, we create `etc/rspamd/override.d/metrics.conf` with the following content:

~~~ucl
# /etc/rspamd/override.d/metrics.conf
actions {
    reject = 150;
    add_header = 6;
    greylist = 4;
}
~~~

You need to define complete objects to override existing ones. For example, you **cannot** write something like

~~~ucl
# /etc/rspamd/override.d/metrics.conf
actions {
    reject = 150;
}
~~~

as this will set the other actions to be undefined. Also, you should notice that individual files are included **within** section:

    section { .include "..."; }

Hence, you don't need to repeat `section { ... }` inside the file included.

### Setting listening interface

Rspamd's normal worker will, by default, listen on all interfaces on port 11333. If you're running Rspamd on the same machine as your mailer (or whatever will be querying it) you might want to set this to 'localhost' instead. This option should be overrided in `/etc/rspamd/override.d/worker-normal.inc` file:

~~~ucl
# /etc/rspamd/override.d/worker-normal.inc
bind_socket = "*:11333";
~~~

If you plan to leave this as is you may wish to use a firewall to restrict access to your machine.

### Setting the controller password

Rspamd requires a password when queried from non-trusted IPs, except for scanning messages which is unrestricted (the default config trusts the loopback interface). This is configured in the file `/etc/rspamd/local.d/worker-controller.inc`. The config to be modified is shown below (replace 'q1' with your chosen password):

~~~ucl
# /etc/rspamd/local.d/worker-controller.inc
password = "q1";
~~~

Optionally you may set `enable_password` - if set, data-changing operations (such as Bayes training or fuzzy storage) will require this password. For example:

~~~ucl
# /etc/rspamd/local.d/worker-controller.inc
enable_password = "q2";
~~~

Moreover, you can store an encrypted password for better security. To generate such a password just type

	$ rspamadm pw
	Enter passphrase:
	$1$4mqeynj3st9pb7cgbj6uoyhnyu3cp8d3$59y6xa4mrihaqdw3tf5mtpzg4k7u69ypebc3yba8jdssoh39x16y

Then you can copy this string and store it in the configuration file. Rspamd uses the [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) algorithm that makes it very hard to brute-force this password even if it has been compromised. From the version 1.3, Rspamd also support [Catena](https://eprint.iacr.org/2013/525.pdf) password hashing scheme which makes brute-force attacks even more memory- and computationally expensive. It is available via `--type` option:

        $ rspamadm pw --type catena
        Enter passphrase:
        $2$g95ywihfinjqx4r69u6mgfs9cqbfq1ay$1h4bm5uod9njfu3hdbwd3w5xf5d9u8gb7i9xnimm5u8ddq3c5byy

For the list of all available hashing schemes, use `--list` option:

        $ ./rspamadm pw --list
        pbkdf2: PBKDF2-blake2b - standard CPU intensive "slow" KDF using blake2b hash function
        catena: Catena-Butterfly - modern CPU and memory intensive KDF

### Setting up the WebUI

WebUI is managed by a controller worker but you might want to proxy its requests using nginx, for example, to add `TLS` support. Here is a minimal setup required for nginx to do that:

<div>
<a class="btn btn-info btn-block btn-code" data-toggle="collapse" data-target="#nginx_cf"><i class="fa fa-caret-square-o-down fa-pull-right"></i>nginx.conf</a><div id="nginx_cf" class="collapse collapse-block"><pre><code>
{% highlight nginx %}
worker_processes  2;
user www-data www-data;

pid        /var/run/nginx.pid;

events {
        worker_connections 8192;
        use epoll;
}

http {
    include       mime.types;
    default_type  text/plain;

    sendfile  on;
    tcp_nopush   on;
    tcp_nodelay on;

    gzip  on;

    server {
        listen 443 ssl;
        add_header Strict-Transport-Security "max-age=31536000; includeSubdomains";
        add_header X-Content-Type-Options nosniff;
        add_header X-Frame-Options SAMEORIGIN;
        add_header X-XSS-Protection "1; mode=block";

        include ssl.conf;
        ssl_certificate /var/lib/acme/live/mail.example.com/fullchain;
        ssl_trusted_certificate /var/lib/acme/live/mail.example.com/fullchain;
        ssl_certificate_key /var/lib/acme/live/mail.example.com/privkey;

        server_name example.com;

        location / {
                proxy_pass  http://127.0.0.1:11334;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header Host $http_host;
        }
        ssl on;
		ssl_protocols TLSv1.2 TLSv1.1 TLSv1;

		ssl_ciphers "EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA256:EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA384:EDH+aRSA+AESGCM:EDH+aRSA+SHA256:EDH+aRSA:EECDH:!aNULL:!eNULL:!MEDIUM:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:!RC4:!SEED";
		ssl_prefer_server_ciphers on;
		ssl_session_cache builtin;
		ssl_session_timeout 1m;
		ssl_stapling on;
		ssl_stapling_verify on;
		server_tokens off;
		# Do not forget to generate custom dhparam using
		# openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048
		ssl_dhparam /etc/nginx/dhparam.pem;
		ssl_ecdh_curve prime256v1;
	}
}
{% endhighlight %}
</code>
</pre>
</div>
</div>

You might also use subdirs, as suggested by [@julienmalik](https://github.com/julienmalik):

<div>
<a class="btn btn-info btn-block btn-code" data-toggle="collapse" data-target="#nginx_cf1"><i class="fa fa-caret-square-o-down fa-pull-right"></i>nginx.conf</a><div id="nginx_cf1" class="collapse collapse-block"><pre><code>
{% highlight nginx %}
location /rspamd/ {
    proxy_pass       http://localhost:11334/;

    proxy_set_header Host      $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
{% endhighlight %}
</code>
</pre>
</div>
</div>

Alternatively, you could setup HTTP authentication in nginx itself.

## Setup Redis statistics

From version 1.1, it is also possible to specify Redis as a backend for statistics and caching of learned messages. Redis is recommended for clustered configurations as it allows simultaneous learning and checking and, besides, is very fast. To setup Redis, you could specify `redis` backend for a classifier (cache is set to the same servers accordingly).

{% highlight ucl %}
classifier {
    tokenizer {
        name = "osb";
    }
    name = "bayes";
    min_tokens = 11;
    backend = "redis";
    servers = "127.0.0.1";

    statfile {
        symbol = "BAYES_SPAM";
    }
    statfile {
        symbol = "BAYES_HAM";
    }
    autolearn = true;
}
{% endhighlight %}

For other possibilities please read the full [documentation]({{ site.baseurl }}/doc/configuration/statistic.html). The more specific Redis related documentation can be found [here]({{ site.baseurl }}/doc/configuration/redis.html).

## Adjusting scores and actions

Unlike SA where there are only `spam` and `ham` results, Rspamd supports five levels of results called `actions`:

+ `no action` - ham message
+ `greylist` - turn on adaptive greylisting (which is also used on higher levels)
+ `add header` - adds Spam header (meaning soft-spam action)
+ `rewrite subject` - rewrite subject to `*** SPAM *** original subject`
+ `reject` - ultimately reject message

Each action can have its own score limit which can be modified by user settings. Rspamd assumes the following order of action scores: `no action` <= `greylist` <= `add header` <= `rewrite subject` <= `reject`.

Actions are **NOT** performed by Rspamd itself - they are just recommendations for the MTA (via Rmilter, for example) which performs the necessary actions, such as adding headers or rejecting mail.

SA `spam` is almost equal to Rspamd `add header` action in the default setup. With this action, users will be able to check for messages in their `Junk` or `Spam` folder which is usually a desired behaviour.

Scores and action settings are defined in the `metric` section. To override existing settings, or add scores for new symbols, you can use the `rspamd.conf.local` file. Here is an example of altering the `reject` action, changing the existing symbol and adding new symbol:

{% highlight ucl %}
metric "default" {
    actions {
        reject = 900; # Set higher reject score
    }

    symbol "MAILLIST" {
        score = -4.1; # Rewrite score
    }

    symbol "MY_SYMBOL" {
        score = 2.1;
        description = "My new symbol";
    }
}
{% endhighlight %}

## Configuring maps

Another feature of Rspamd is maps support. Maps are lists of values, for example, domain names or ip/networks listed in an external file or by HTTP that are periodically monitored by Rspamd and reloaded in case of updates. This technique is useful for writing your own rules, whitelisting or blacklisting some networks and so on. The important difference with maps is that rspamd restart is not required when those lists are changed. Maps are defined as `URI` strings:

* `http://example.com/file.map` - HTTP map (server should respect `If-Modified-Since` header to avoid unnecessary updates)
* `file:///path/to/map` - file map
* `/path/to/map` - alternative syntax for file map

Within maps you can use whitespace or comments. For example, here is an example of ip/network map:

    # Example map
    127.0.0.1 # localhost

    10.0.0.0/8
    fe80::/64

There is a special module called `multimap` that allows you to define your own maps without writing lua rules. You can check the module's [documentation]({{ site.baseurl }}/doc/modules/multimap.html) and create your configuration in `rspamd.conf.override`.

## Configuring RBLs

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

### Using rspamc console routine

`rspamc` implements a feature-complete client for Rspamd. For detailed documentation refer to `man rspamc`.

Common use-cases for `rspamc` include:

* Scanning messages stored on disk:

    rspamc < file.eml
    rspamc file.eml
    rspamc directory1/ directory2/*.eml

* Training the Bayesian classifier

    rspamc learn_spam < file.eml
    rspamc learn_ham file.eml
    rspamc -c "bayes2" learn_spam directory1/ directory2/*.eml

* Administering fuzzy storage

    rspamc -f 1 -w 1 fuzzy_add file.eml
    rspamc -f 2 fuzzy_del file2.eml

* Acting as a local delivery agent (read the [integration document]({{ site.baseurl }}/doc/integration.html))

### The rspamadm command

Rspamadm is a new utility that is intended to manage rspamd directly. It comes with embedded help that can be displayed by typing:

    % rspamadm help
    Rspamadm 1.1.0
    Usage: rspamadm [global_options] command [command_options]

    Available commands:
       pw                 Manage rspamd passwords
       keypair            Create encryption key pairs
       configtest         Perform configuration file test
       fuzzy_merge        Merge fuzzy databases
       configdump         Perform configuration file dump
       control            Manage rspamd main control interface
       confighelp         Shows help for configuration options

For example, it is possible to get help for a specific configuration option by typing something like

    rspamadm confighelp -k fuzzy

### Using mail system utilities

It is also useful to have a simple `Sieve` script to place all messages marked as spam in the `Junk` folder. Here is an example of such a script (~/.dovecot.sieve):

{% highlight nginx %}
require ["fileinto"];

if header :is "X-Spam" "Yes" {
        fileinto "Junk";
}
{% endhighlight %}

You can also setup rspamc to learn via passing messages to a certain email address. I recommend using `/etc/aliases` for these purposes and `mail-redirect` command (e.g. provided by [Mail Redirect addon](https://addons.mozilla.org/en-GB/thunderbird/addon/mailredirect/) for `Thunderbird` MUA). The desired aliases could be the following:

	learn-spam123: "| rspamc learn_spam"
	learn-ham123: "| rspamc learn_ham"

You'd need some less predictable aliases to avoid sending messages to such addresses by some adversary or just by a mistake to prevent statistics pollution.

There is also an add-on for Thunderbird MUA written by Alexander Moisseev to visualise Rspamd stats. You can download it from its [homepage](https://addons.mozilla.org/en-GB/thunderbird/addon/rspamd-spamness/). You'd need to add extended spam headers (`X-Spamd-Result`) with Rmilter and/or (from add-on's version 0.8.0) `X-Spam-Score` and `X-Spam-Report` headers with Exim to make the whole setup work.

To enable extended spam headers in Rmilter add the following line to `rmilter.conf`:

{% highlight ucl %}
spamd {
...
        extended_spam_headers = yes;
}
{% endhighlight %}

To enable headers in Exim refer to the "Integration with Exim MTA" section of the [MTA integration]({{ site.baseurl }}/doc/integration.html) document.

Here is a screenshot of this addon in use:

<img class="img-responsive" src="{{ site.baseurl }}/img/thunderbird_rspamd.png">

### Using the WebUI

Rspamd has a built-in WebUI which supports setting metric actions and scores; Bayes training and scanning messages - for more information see the [WebUI documentation](https://rspamd.com/webui).
