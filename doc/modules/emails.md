---
layout: doc_modules
title: Emails module
---

# Emails module

This module implements emails filtering based on DNS or static lists.

## Module configuration

The configuration for this module is quite common to [`surbl` module]({{ site.baseurl }}/doc/modules/surbl.html). You can define multiple `rule` section where it is possible to define either static maps or DNS lists:

~~~ucl
# /etc/rspamd/local.d/emails.conf

rule "EMAILS_DNSBL" {
  dnsbl = "emailbl.rambler.ru";
  domain_only = true;
}

rule "EMAILS_STATIC" {
  map = "/etc/rspamd/bad_emails.list";
}
~~~

In the first rule, we define a symbol "EMAILS_DNSBL" which checks DNS list in `dnsbl` settings. The option `domain_only` specifies that check should be performed merely for a domain part: e.g. `user@example.com` will be checked as `example.com.emailbl.rambler.ru` DNS name.

The second rule defines a static list of emails. Since `domain_only` is not specified, the full email will be checked. For example, you can include something like 

    user@example.com

in that list. It is also possible to use regular expressions in this list:

    /^[^@]+@example.com$/i