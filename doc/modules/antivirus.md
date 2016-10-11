---
layout: doc_modules
title: Antivirus module
---

# Antivirus module

Antivirus module (new in Rspamd 1.4) provides integration with virus scanners. Currently supported are ClamAV & F-Prot.

### Configuration

By default, given [Redis](/doc/configuration/redis.html) is configured globally and `antivirus` is not explicitly disabled in redis configuration, results are cached in Redis according to message checksums.

Settings should be added to `rspamd.conf.local`:

~~~ucl
antivirus {
	# multiple scanners could be checked, for each we create a configuration block with an arbitrary name
	first {
		# if `true` only messages with non-image attachments will be checked (default true)
		attachments_only = true;
		# symbol to add (add it to metric if you want non-zero weight)
		symbol = "CLAM_VIRUS";
		# type of scanner: currently `clamav` or `fprot`
		type = "clamav";
		# servers to query (if port is unspecified, scanner-specific default is used)
		# can be specified multiple times to pool servers
		servers = "127.0.0.1:3310";
		# if `patterns` is specified virus name will be matched against provided regexes and the related
		# symbol will be yielded if a match is found. If no match is found, default symbol is yielded.
		patterns {
			# symbol_name = "pattern";
			JUST_EICAR = "^Eicar-Test-Signature$";
		}
		# `whitelist` points to a map of IP addresses. Mail from these addresses is not scanned.
		whitelist = "/etc/rspamd/antivirus.wl";
	}
}
~~~
