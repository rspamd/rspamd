# Scanning outbound mail

## Why and how to scan outbound mail

Outbound spam can be extremely damaging to the ability of your system to successfully deliver mail so it is pragmatic to avoid delivering spam. Unlike inbound spam, outbound spam outbreaks require incident response (e.g. changing passwords of affected accounts). If the spam outbreak was identified by automated content scanning human verification could be helpful- but may be in violation of applicable privacy laws or company policies. Please consult your legal counsel & company stakeholders to determine policies regarding handling of suspected outbound spam that are suitable for your purposes. How such mail should ultimately be handled is beyond the scope of this document (though it may eventually be extended to provide some example recipes).

## Scanning outbound with Rspamd

Rspamd tries to be suitable for outbound scanning with no or little configuration. With proper [integration](https://rspamd.com/doc/integration.html) Rspamd should have knowledge of whether mail was sent by an authenticated user (and which) as well as the IP address the mail was received from. If mail was received from an authenticated user or an IP address listed in [local_addrs](https://rspamd.com/doc/configuration/options.html) several checks are immutably disabled: 

 - [DKIM](https://rspamd.com/doc/modules/dkim.html): checking is disabled; signing is enabled
 - [DMARC](https://rspamd.com/doc/modules/dmarc.html): is disabled
 - [Greylist](https://rspamd.com/doc/modules/greylisting.html): is disabled
 - Hfilter: only URL-checks are applied
 - [IP Score](https://rspamd.com/doc/modules/ip_score.html): is disabled
 - [One Received header policy](https://rspamd.com/doc/modules/once_received.html): is disabled
 - [Ratelimit](https://rspamd.com/doc/modules/ratelimit.html): only `user` ratelimit is applied (to authenticated users- does not deal with `local_addrs`)
 - [RBL](https://rspamd.com/doc/modules/rbl.html): RBLs are disabled according to `exclude_users` and `exclude_local` settings (all save for `RAMBLER_EMAILBL`)
 - [Replies](https://rspamd.com/doc/modules/replies.html): action is not forced
 - [SPF](https://rspamd.com/doc/modules/spf.html): is disabled

Additionally, it is possible to disable/enable checks selectively and/or rescore checks for your authenticated users or relay IPs using [settings module](https://rspamd.com/doc/configuration/settings.html).

### Rmilter

### Exim
