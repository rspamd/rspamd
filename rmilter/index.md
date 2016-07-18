---
layout: rmilter_main
title: About rmilter
---

## Introduction

Rmilter is used to integrate rspamd and `milter` compatible MTA, for example Postfix or Sendmail. It also performs other useful functions for email filtering including:

- Virus scanning using [Clamav](http://clamav.net)
- Spam scanning using Rspamd
- Greylisting using redis storage
- Ratelimit using redis storage
- Replies check (whitelisting replies to sent messages)
- Passing certain messages to redis pub/sub channels
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
            <a class="btn btn-social btn-primary btn-block" href="/rmilter/configuration.html"><i class="fa fa-file-text-o"></i> Rmilter configuration</a>
        </div>
        <div class="col-sm-9 col-xs-12">
            <p>Rmilter configuration format is described in here.</p>
        </div>
    </div>
</div>

## Postfix settings

Here is a scheme that demonstrates Rspamd and Rmilter integration using Postfix MTA:

<img class="img-responsive" src="/img/rspamd-schemes.007_2.png">

There are several useful settings for postfix to work with this milter:

    smtpd_milters = unix:/var/run/rmilter/rmilter.sock
    milter_mail_macros =  i {mail_addr} {client_addr} {client_name} {auth_authen}
    milter_protocol = 6

<div style="padding-top:20px;"></div>

## Useful rmilter recipies

This section contains a number of useful configuration recipes and best practices for Rmilter.


### Setup DKIM signing of outcoming email for authenticated users

With this setup you should generate keys and store them in `/etc/dkim/<domain>.<selector>.key`
This could be done, for example by using `opendkim-genkey`:

    opendkim-genkey --domain=example.com --selector=dkim

That will generate `dkim.private` file with private key and `dkim.txt` with the suggested `TXT` record for your domain.

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

Please note, that Rmilter will sign merely mail for the **authenticated** users, hence you should also ensure that `{auth_authen}` macro
is passed to milter on `MAIL FROM` stage:

    milter_mail_macros =  i {mail_addr} {client_addr} {client_name} {auth_authen}

### Setup whitelisting of reply messages

It is possible to store `Message-ID` headers for authenticated users and whitelist replies to that messages by using of Rmilter. To enable this
feature, please ensure that you have `redis` server running and add the following lines to Redis section:

    redis {
      ...
      # servers_id - redis servers used for message id storing, can not be mirrored
      servers_id = localhost;

      # id_prefix - prefix for extracting message ids from redis
      # Default: empty (no prefix is prepended to key)
      id_prefix = "message_id.";
    }
