# DKIM module

This module checks [DKIM](http://www.dkim.org/) signatures for emails scanned.
DKIM signatures can establish that this specific message has been signed by a trusted
relay. For example, if a message comes from `gmail.com` then a valid DKIM signature
means that this message was definitely signed by `gmail.com` (unless gmail.com private
key has been compromised, which is not a likewise case).

## Principles of work

Rspamd can deal with many types of DKIM signatures and messages canonicalisation.
The major difficulty with DKIM are line endings: many MTA treat them differently which
leads to broken signatures. Basically, rspamd treats all line endings as `CR+LF` that
is compatible with the most of DKIM implementations.

## Configuration

DKIM module has several useful configuration options:

- `dkim_cache_size` (or `expire`) - maximum size of DKIM keys cache
- `whitelist` - a map of domains that should not be checked with DKIM (e.g. if that domains have totally broken DKIM signer)
- `domains` - a map of domains that should have more strict scores for DKIM violation
- `strict_multiplier` - multiply the value of symbols by this value if received from `domains` map
- `trusted_only` - do not check DKIM signatures for all domains but those which are from the `domains` map
- `skip_multi` - skip DKIM check for messages with multiple signatures

The last option can help for some circumstances when rspamd lacks the proper support of
multiple DKIM signatures. Unfortunately, with some mailing lists, or other software
this option could be useful to reduce false positives rate as rspamd deals with
multiple signatures poorly: it just uses the first one to check. On the other hand,
the proper support of multiple DKIM signatures is planned to be implemented in rspamd 
in the next releases, which will make this option meaningless.