# DMARC module

DMARC is a special technology that allows domains to define theirs `SPF` and `DKIM` policies. For example, a domain
might define that all messages sent must have valid DKIM signature and permissive SPF policies. That is useful for
domains that deal with payments or other confidential stuff (such as e-banking). Conjunction of SPF, DKIM and DMARC
allows to avoid or filter fraud for such domains.

Moreover, DMARC allows to set a specific address to collect abused messages. This can be useful for fraud prevention as well.
DMARC is set using DNS `TXT` record, called `_dmarc.domain.com`. It's format is standartized and here is, for example a record
that specifies strict policy for SPF and DKIM:

    v=DMARC1; p=reject; rua=mailto:d@rua.agari.com; ruf=mailto:dk@bounce.paypal.com,mailto:d@ruf.agari.com

This record also specifies email addresses for abuse reports (for realtime and archives).

## DMARC in rspamd

Rspamd supports DMARC policies and also can store information about mails that have violated policies for collecting statistics and sending reports.
Please mention, that rspamd itself cannot send reports, it merely stores sufficient data in `redis` that could be used for generating DMARC reports by an external tool (not shipped with rspamd now).

DMARC configuration is very simple:

~~~ucl
dmarc {
    servers = "localhost:6390";
    key_prefix = "dmarc_"; # Keys would have format of dmarc_domain.com
}
~~~

When you have this module enabled, it also adds symbols:

- `DMARC_POLICY_ALLOW`: SPF **and** DKIM policies are satisfied
- `DMARC_POLICY_REJECT`: SPF **or** DKIM policies are violated
- `DMARC_POLICY_QUARANTINE`: Message is suggested to be quarantined by DMARC policy
- `DMARC_POLICY_SOFTFAIL`: DNS or other temporary error

When a message violates DMARC policy, rspamd adds the following information to `redis` server:

    unixtime,ip,spf_result,dkim_result

where results are `true` or `false` meaning allow and reject values accordingly.
Unixtime and IP are inserted in text form. Keys are therefore `lists` in redis terminology.

Keys are inserted to redis servers when a server is selected by hash value from sender's domain.
