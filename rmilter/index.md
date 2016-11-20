---
layout: rmilter_main
title: About rmilter
---

## Introduction

Rmilter is used to integrate Rspamd and `milter` compatible MTA, for example Postfix or Sendmail. It also performs other useful functions for email filtering including:

- Virus scanning using [ClamAV](http://clamav.net)
- Spam scanning using Rspamd
- Greylisting using Redis storage
- Ratelimit using Redis storage
- Replies check (whitelisting replies to sent messages)
- Passing certain messages to Redis Pub/Sub channels
- DKIM signing

<div>
    <div class="row" style="margin-top: 20px; margin-bottom: 20px;">
        <div class="col-sm-3 col-xs-12">
            <a class="btn btn-social btn-github btn-block" href="http://github.com/vstakhov/rmilter"><i class="fa fa-github"></i> Rmilter project</a>
        </div>
        <div class="col-sm-9 col-xs-12">
            <p>Rmilter project page can be found on GitHub.</p>
        </div>
    </div>
    <div class="row" style="margin-top: 20px; margin-bottom: 20px;">
        <div class="col-sm-3 col-xs-12">
            <a class="btn btn-social btn-primary btn-block" href="{{ site.baseurl }}/rmilter/configuration.html"><i class="fa fa-file-text-o"></i> Rmilter configuration</a>
        </div>
        <div class="col-sm-9 col-xs-12">
            <p>Rmilter configuration format is described in here.</p>
        </div>
    </div>
</div>

## Postfix settings

Here is a scheme that demonstrates Rspamd and Postfix MTA integration using Rmilter:

<img class="img-responsive" src="{{ site.baseurl }}/img/rspamd-schemes.007_2.png">

There are several useful settings for Postfix to work with this milter:

    smtpd_milters = unix:/var/run/rmilter/rmilter.sock
    milter_mail_macros =  i {mail_addr} {client_addr} {client_name} {auth_authen}
    milter_protocol = 6

<div style="padding-top:20px;"></div>

## Useful Rmilter recipes

This section contains a number of useful configuration recipes and best practices for Rmilter.


### Adding local changes to Rmilter configuration

Since version 1.9, Rmilter supports macros `.try_include` that can be used to conditionally include some user specific file. There is also globbing support in all `include` macros, so you can use `*` or `?` in your patterns. By default, Rmilter tries to include `/etc/rmilter.conf.local` and then all files that match the pattern `/etc/rmilter.conf.d/*.conf` (there could be a different prefix for your system). The settings are natively overridden by files inside files included. Hence, settings that are defined **later** will override settings that are defined earlier:

~~~ucl
# /etc/rmilter.conf
spamd {
    servers = localhost:11333; # overridden
}

# Includes are after the main definition
.try_include /etc/rmilter.conf.local
.try_include /etc/rmilter.conf.d/*.conf
~~~

~~~ucl
# /etc/rmilter.conf.local
spamd {
    servers = example.com:11333; # overridden
    timeout = 5s; # added
}
~~~

~~~ucl
# /etc/rmilter.conf.d/spamd.conf
spamd {
    servers = other.com:11333;
}
~~~

will produce the following configuration:

~~~ucl
# resulting configuration
spamd {
    servers = other.com:11333;
    timeout = 5s;
}
~~~

It is also possible to add elements to lists (from Rmilter `1.9.2`) using `+=` operator:

~~~ucl
# /etc/rmilter.conf.local
spamd {
    servers = example.com:11333;
    timeout = 5s; # added
}
~~~

~~~ucl
# /etc/rmilter.conf.d/spamd.conf
spamd {
    servers += other.com:11333;
}
~~~

will produce the following configuration:

~~~ucl
# resulting configuration
spamd {
    servers = example.com:11333, other.com:11333;
    timeout = 5s;
}
~~~

Using of empty lists can remove the default lists content:

~~~ucl
ratelimit {
    whitelist = ; # Will remove the default whitelist
}
~~~

### How to disable DKIM signing, greylisting and ratelimit in Rmilter

From version `1.9.1` it is possible to specify `enable` option in `greylisting` and `ratelimit` sections. It is also possible for `dkim` section since `1.9.2`. These options are `true` by default. Here is an example of configuration where greylisting and ratelimit are disabled:

~~~ucl
# /etc/rmilter.conf.local
limits {
    enable = false;
}
greylisting {
    enable = false;
}
dkim {
    enable = false;
}
~~~

### Setup DKIM signing of outcoming email for authenticated users

With this setup you should generate keys and store them in `/etc/dkim/<domain>.<selector>.key`
This could be done, for example by using `opendkim-genkey`:

    opendkim-genkey --domain=example.com --selector=dkim

That will generate `dkim.private` file with private key and `dkim.txt` with the suggested `TXT` record for your domain.

~~~ucl
dkim {
    domain {
        key = /etc/dkim;
        domain = "*";
        selector = "dkim";
    };
    header_canon = relaxed;
    body_canon = relaxed;
    sign_alg = sha256;
};
~~~

Please note, that Rmilter will sign merely mail for the **authenticated** users, hence you should also ensure that `{auth_authen}` macro
is passed to milter on `MAIL FROM` stage:

    milter_mail_macros =  i {mail_addr} {client_addr} {client_name} {auth_authen}

### Setup whitelisting of reply messages

It is possible to store `Message-ID` headers for authenticated users and whitelist replies to that messages by using of Rmilter. To enable this
feature, please ensure that you have Redis server running and add the following lines to `redis` section (or add `conf.d/redis.conf` file):

~~~ucl
redis {
    # servers_id - Redis servers used for message id storing, can not be mirrored
    servers_id = localhost;

    # id_prefix - prefix for extracting message ids from Redis
    # Default: empty (no prefix is prepended to key)
    id_prefix = "message_id.";
}
~~~
