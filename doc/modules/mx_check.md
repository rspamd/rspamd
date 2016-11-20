---
layout: doc_modules
title: MX Check module
---

# MX Check module

The MX Check module checks if the domain in a message's SMTP FROM addresses (or the domain in HELO in case SMTP FROM is empty) has at least one connectable MX. If a connectable MX is found this information is cached in [Redis]({{ site.baseurl }}/doc/configuration/redis.html).

Example configuration indicating default settings is shown below. Symbols indicated by configuration should be added to metric to provide non-zero scoring. At minimum you should add `mx_check { }` to `rspamd.conf.local` to enable the module.

~~~ucl
mx_check {
  # connection timeout in seconds
  timeout = 1.0;
  # symbol yielded if no MX is connectable
  symbol_bad_mx = "MX_INVALID";
  # symbol yielded if no MX is found
  symbol_no_mx = "MX_MISSING";
  # symbol yielded if MX is connectable
  symbol_good_mx = "MX_GOOD";
  # lifetime of redis cache - 1 day by default
  expire = 86400;
  # prefix used for redis key
  key_prefix = "rmx";
}
~~~
