---
layout: rmilter_main
title: About rmilter
---

## Introduction

Rmilter is used to integrate Rspamd and `milter` compatible MTA, for example Postfix or Sendmail. 

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

## Project state

This project is now not under active development, however, bug fixes and Rspamd integration features are still considered.

Historically, Rmilter supported many other features besides Rspamd integration. So far, all these features are implemented in Rspamd which allows to simplify integration with different MTA (e.g. Exim, Haraka or other non-milter compatible servers). Therefore, if you use this functionality you should consider switching it to Rspamd where all equal features are usually better implemented and have active and actual support.

The list of features includes the following ones:

- Greylisting - provided by [greylisting module](https://rspamd.com/doc/modules/greylisting.html)
- Ratelimit - is done by [ratelimit module](https://rspamd.com/doc/modules/ratelimit.html)
- Replies whitelisting - is implemented in [replies module](https://rspamd.com/doc/modules/replies.html)
- Antivirus filtering - provided now by [antivirus module](https://rspamd.com/doc/modules/antivirus.html)
- DCC checks - are now done in [dcc module](https://rspamd.com/doc/modules/dcc.html)
- Dkim signing - can be done now by using of [dkim module](https://rspamd.com/doc/modules/dkim.html#dkim-signatures) and also by a more simple [dkim signing module](https://rspamd.com/doc/modules/dkim_signing.html)

All duplicating features are still kept in Rmilter for compatibility reasons. However, no further development or bug fixes will likely be done for them.

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

These options are in their default enabled states merely for compatibility purposes. In future Rmilter releases, they will be **DISABLED** by default.

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