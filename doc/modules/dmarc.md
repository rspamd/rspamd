---
layout: doc_modules
title: DMARC module
---
# DMARC module

DMARC is a technology leveraging SPF & DKIM which allows domain owners to publish policies regarding how messages bearing
their domain in the RFC5322.From field should be handled (for example to quarantine or reject messages which do not have an
aligned DKIM or SPF identifier) and to elect to receive reporting information about such messages (to help them identify
abuse and/or misconfiguration and make informed decisions about policy application).

## DMARC in rspamd

The default configuration for the DMARC module in rspamd is an empty collection:

~~~ucl
dmarc {
}
~~~

This is enough to enable the module and check/apply DMARC policies.

Symbols added by the module are as follows:

- `DMARC_BAD_POLICY`: Policy was invalid or multiple policies found in DNS
- `DMARC_NA`: Domain in From header has no DMARC policy or From header is missing
- `DMARC_POLICY_ALLOW`: Message was authenticated & allowed by DMARC policy
- `DMARC_POLICY_REJECT`: Authentication failed- rejection suggested by DMARC policy
- `DMARC_POLICY_QUARANTINE`: Authentication failed- quarantine suggested by DMARC policy
- `DMARC_POLICY_SOFTFAIL`: Authentication failed- no action suggested by DMARC policy

Rspamd is able to store records in `redis` which could be used to generate DMARC aggregate reports but there is as of yet no available tool to generate such reports from these. Format of the records stored in `redis` is as follows:

    unixtime,ip,spf_result,dkim_result,dmarc_disposition

where spf and dkim results are `true` or `false` indicating wether an aligned spf/dkim identifier was found and dmarc_disposition is one of `none`/`quarantine`/`reject` indicating policy applied to the message.

These records are added to a list named $prefix$domain where $domain is the domain which defined policy for the message being reported on and $prefix is the value of the `key_prefix` setting (or "dmarc_" if this isn't set).

Keys are inserted to redis servers when a server is selected by hash value from sender's domain.

To enable storing of report information, `reporting` must be set to `true`.

Actions can be forced for messages based on DMARC disposition as demonstrated in example config below.

~~~ucl
dmarc {
	# Enables storing reporting information to redis
	reporting = true;
	# If Redis server is not configured below, settings from redis {} will be used
	#servers = "127.0.0.1:6379"; # Servers to use for reads and writes (can be a list)
	# Alternatively set read_servers / write_servers to split reads and writes
	# To set custom prefix for redis keys:
	#key_prefix = "dmarc_";
	# Actions to enforce based on DMARC disposition (empty by default)
	actions = {
		quarantine = "add_header";
		reject = "reject";
	}
}
~~~
