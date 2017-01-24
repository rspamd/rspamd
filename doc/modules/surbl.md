---
layout: doc_modules
title: SURBL module
---
# SURBL module

This module performs scanning of URL's found in messages against a list of known
DNS lists. It can add different symbols depending on the DNS replies from a 
specific DNS URL list. It is also possible to resolve domains of URLs and then
check the IP addresses against the normal `RBL` style list.

## Module configuration

The default configuration defines several public URL lists. However, their terms
of usage normally disallows commercial or very extensive usage without purchasing
a specific sort of license.

Nonetheless, they can be used by personal services or low volume requests free
of charge.

~~~ucl
surbl {
    # List of domains that are not checked by surbl
    whitelist = "file://$CONFDIR/surbl-whitelist.inc";
    # Additional exceptions for TLD rules
    exceptions = "file://$CONFDIR/2tld.inc";

    rule {
        # DNS suffix for this rule
        suffix = "multi.surbl.org";
        symbol = "SURBL_MULTI";
        bits {
            # List of bits ORed when reply is given
            JP_SURBL_MULTI = 64;
            AB_SURBL_MULTI = 32;
            MW_SURBL_MULTI = 16;
            PH_SURBL_MULTI = 8;
            WS_SURBL_MULTI = 4;
            SC_SURBL_MULTI = 2;
        }
    }
    rule {
        suffix = "multi.uribl.com";
        symbol = "URIBL_MULTI";
        bits {
            URIBL_BLACK = 2;
            URIBL_GREY = 4;
            URIBL_RED = 8;
        }
    }
    rule {
        suffix = "uribl.rambler.ru";
        # Also check images
        images = true;
        symbol = "RAMBLER_URIBL";
    }
    rule {
        suffix = "dbl.spamhaus.org";
        symbol = "DBL";
        # Do not check numeric URL's
        noip = true;
    }
    rule {
        suffix = "uribl.spameatingmonkey.net";
        symbol = "SEM_URIBL_UNKNOWN";
        bits {
            SEM_URIBL = 2;
        }
        noip = true;
    }
    rule {
        suffix = "fresh15.spameatingmonkey.net";
        symbol = "SEM_URIBL_FRESH15_UNKNOWN";
        bits {
            SEM_URIBL_FRESH15 = 2;
        }
        noip = true;
    }
}
~~~

In general, the configuration of `surbl` module is definition of DNS lists. Each
list must have suffix that defines the list itself and optionally for some lists
it is possible to specify either `bit` or `ips` sections.

Since some URL lists do not accept `IP` addresses, it is also possible to disable sending of URLs with IP address in the host to such lists. That could be done by specifying `noip = true` option:

~~~ucl
    rule {
        suffix = "dbl.spamhaus.org";
        symbol = "DBL";
        # Do not check numeric URL's
        noip = true;
    }
~~~

It is also possible to check HTML images URLs using URL blacklists. Just specify `images = true` for such list and you are done:

~~~ucl
    rule {
        suffix = "uribl.rambler.ru";
        # Also check images
        images = true;
        symbol = "RAMBLER_URIBL";
    }
~~~

## Principles of operation

In this section, we define how `surbl` module performs its checks.

### TLD composition

By default, we want to check some top level domain, however, many domains contain
two components while others can have 3 or even more components to check against the
list. By default, rspamd takes top level domain as defined in the [public suffixes](https://publicsuffix.org).
Then one more component is prepended, for example:

    sub.example.com -> [.com] -> example.com
    sub.co.uk -> [.co.uk] -> sub.co.uk

However, sometimes even more levels of domain components are required. In this case,
the `exceptions` map can be used. For example, if we want to check all subdomains of
`example.com` and `example.co.uk`, then we can define the following list:

    example.com
    example.co.uk

Here are new composition rules:

    sub.example.com -> [.example.com] -> sub.example.com
    sub1.sub2.example.co.uk -> [.example.co.uk] -> sub2.example.co.uk

### DNS composition

SURBL module composes the DNS request of two parts:

- TLD component as defined in the previous section;
- DNS list suffix

For example, to form a request to multi.surbl.org, the following applied:

    example.com -> example.com.multi.surbl.com

### Results parsing

Normally, DNS blacklists encode reply in A record from some private network
(namely, `127.0.0.0/8`). Encoding varies from one service to another. Some lists
use bits encoding, where a single DNS list or error message is encoded as a bit
in the least significant octet of the IP address. For example, if bit 1 encodes `LISTA`
and bit 2 encodes `LISTB`, then we need to perform bitwise `OR` for each specific bit
to decode reply:

     127.0.0.3 -> LISTA | LISTB -> both bit symbols are added
     127.0.0.2 -> LISTB only
     127.0.0.1 -> LISTA only

This encoding can save DNS requests to query multiple lists one at a time.

Some other lists use direct encoding of lists by some specific addresses. In this
case you should define results decoding principle in `ips` section not `bits` since
bitwise rules are not applicable to these lists. In `ips` section you explicitly
match the ip returned by a list and its meaning.

## IP lists

From rspamd 1.1 it is also possible to do two step checks:

1. Resolve IP addresses of each URL
2. Check each IP resolved against SURBL list

In general this procedure could be represented as following:

* Check `A` or `AAAA` records for `example.com`
* For each ip address resolve it using reverse octets composition: so if IP address of `example.com` is `1.2.3.4`, then checks would be for `4.3.2.1.uribl.tld`

For example, [SBL list](https://www.spamhaus.org/sbl/) of `spamhaus` project provides such functions using `ZEN` multi list. This is included in rspamd default configuration:

~~~ucl
    rule {
        suffix = "zen.spamhaus.org";
        symbol = "ZEN_URIBL";
        resolve_ip = true;
        ips {
            URIBL_SBL = "127.0.0.2";
        }
    }
~~~

## Disabling SURBLs

Rules can be disabled by setting the `enabled` setting to `false`. This allows for easily disabling SURBLs without overriding the full default configuration. The example below could be added to `/etc/rspamd/local.d/surbl.conf` to disable the `RAMBLER_URIBL` URIBL.

~~~ucl
rules {
  "RAMBLER_URIBL" {
    enabled = false;
  }
}
~~~
