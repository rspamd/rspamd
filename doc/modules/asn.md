---
layout: doc_modules
title: ASN module
---

# ASN module

ASN module looks up ASN numbers and some related information: namely country code of ASN owner & subnet in which IP is announced and makes these available to other plugins as mempool variables.

Currently the only supported lookup mechanism is [Team Cymru's DNSBL](http://www.team-cymru.org/IP-ASN-mapping.html).

### Configuration

To use default settings you could add `asn { }` to `rspamd.conf.local`.

~~~ucl
asn {
	# Provider: just "cymru" for now
	provider_type = "cymru";
	# Provider-specific configuration
	provider_info {
		ip4 = "origin.asn.cymru.com";
		ip6 = "origin6.asn.cymru.com";
	}
	# If defined, insert symbol with lookup results
	symbol = "ASN";
}
~~~
