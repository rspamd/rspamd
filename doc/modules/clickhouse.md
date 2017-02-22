---
layout: doc_modules
title: Clickhouse module
---

# Clickhouse module

Clickhouse module pushes a variety of message-related metadata to an instance of [Clickhouse](https://clickhouse.yandex/), an open-source column-oriented DBMS useful for realtime analytics. Information that could be collected includes: senders/recipients/scores of scanned messages and metadata such as DKIM/DMARC/bayes/fuzzy status & information about URLs and attachments.

### Clickhouse usage examples

Clickhouse module is extremely useful to perform statistical researches for mail flows. For example, to find top sending domains for spam and ham:

~~~
SELECT
    From,
    count() AS c
FROM rspamd
WHERE (Date = today()) AND ((Action = 'reject') OR (Action = 'add header'))
GROUP BY From
ORDER BY c DESC
LIMIT 10

┌─From────────────┬──────c─┐
│ xxx.com         │ 152931 │
│ xxx.com         │ 102123 │
│ gmail.com       │  60865 │
│ yahoo.com       │  58832 │
│ xxx.com         │  58082 │
...
└─────────────────┴────────┘
~~~

Or messages with failed DKIM and DMARC groupped by domain:

~~~
SELECT
    From,
    IP,
    count() AS c
FROM rspamd
WHERE (Date = today()) AND (IsDkim = 'reject')
GROUP BY
    From,
    IP
ORDER BY c DESC
LIMIT 10

┌─From─────────────────┬─IP─────────────┬─────c─┐
│ xxx.xxx              │ xx.xx.xx.xx    │ 27542 │
│ xxx.xxx              │ xx.yy.yy.yy    │ 24958 │
...
└──────────────────────┴────────────────┴───────┘
~~~

Or perform some attachments analysis (e.g. top attachments types for Spam):

~~~
SELECT
    count() AS c,
    d
FROM rspamd_attachments
ARRAY JOIN Attachments.ContentType AS d
ANY INNER JOIN
(
    SELECT Digest
    FROM rspamd
    WHERE (Date = today()) AND ((Action = 'reject') OR (Action = 'add header'))
) USING (Digest)
GROUP BY d
ORDER BY c DESC
LIMIT 5

┌──────c─┬─d────────────────────────┐
│ ddd    │ image/jpeg               │
│ ddd    │ image/png                │
│ ddd    │ application/octet-stream │
│ ddd    │ image/gif                │
│ ddd    │ application/msword       │
└────────┴──────────────────────────┘
~~~

Rspamd can also send copies of data for specific domains to a separate tables to simplify analytics.

For mailing lists, Rspamd sends list ids which allows to provide very precise statistics for each particular mailing list:

~~~
SELECT
    ListId,
    IP,
    count() AS c
FROM rspamd
WHERE (Date = today()) AND (ListId != '')
GROUP BY
    ListId,
    IP
ORDER BY c DESC
LIMIT 10

┌─ListId───────────────────────────────┬─IP──────────────┬──────c─┐
│ xxx                                  │ xx.xx.xx.xx     │ dddd   │
...
└──────────────────────────────────────┴─────────────────┴────────┘
~~~

### Clickhouse tables schema

Before using of this module, you need to create certain tables in clickhouse. Here is the desired schema for these tables:

~~~
CREATE TABLE rspamd
(
  Date Date,
  TS DateTime,
  From String,
  MimeFrom String,
  IP String,
  Score Float64,
  NRcpt UInt8,
  Size UInt32,
  IsWhitelist Enum8('blacklist' = 0, 'whitelist' = 1, 'unknown' = 2) DEFAULT CAST('unknown' AS Enum8('blacklist' = 0, 'whitelist' = 1, 'unknown' = 2)),
  IsBayes Enum8('ham' = 0, 'spam' = 1, 'unknown' = 2) DEFAULT CAST('unknown' AS Enum8('ham' = 0, 'spam' = 1, 'unknown' = 2)),
  IsFuzzy Enum8('whitelist' = 0, 'deny' = 1, 'unknown' = 2) DEFAULT CAST('unknown' AS Enum8('whitelist' = 0, 'deny' = 1, 'unknown' = 2)),
  IsFann Enum8('ham' = 0, 'spam' = 1, 'unknown' = 2) DEFAULT CAST('unknown' AS Enum8('ham' = 0, 'spam' = 1, 'unknown' = 2)),
  IsDkim Enum8('reject' = 0, 'allow' = 1, 'unknown' = 2) DEFAULT CAST('unknown' AS Enum8('reject' = 0, 'allow' = 1, 'unknown' = 2)),
  IsDmarc Enum8('reject' = 0, 'allow' = 1, 'unknown' = 2) DEFAULT CAST('unknown' AS Enum8('reject' = 0, 'allow' = 1, 'unknown' = 2)),
  NUrls Int32,
  Action Enum8('reject' = 0, 'rewrite subject' = 1, 'add header' = 2, 'greylist' = 3, 'no action' = 4) DEFAULT CAST('no action' AS Enum8('reject' = 0, 'rewrite subject' = 1, 'add header' = 2, 'greylist' = 3, 'no action' = 4)),
  FromUser String,
  MimeUser String,
  RcptUser String,
  RcptDomain String,
  ListId String,
  Digest FixedString(32)
) ENGINE = MergeTree(Date, (TS, From), 8192)

CREATE TABLE rspamd_attachments (
  Date Date,
  Digest FixedString(32),
  `Attachments.FileName` Array(String),
  `Attachments.ContentType` Array(String),
  `Attachments.Length` Array(UInt32),
  `Attachments.Digest` Array(FixedString(16))
) ENGINE = MergeTree(Date, Digest, 8192)

CREATE TABLE rspamd_urls (
  Date Date,
  Digest FixedString(32),
  `Urls.Tld` Array(String),
  `Urls.Url` Array(String)
) ENGINE = MergeTree(Date, Digest, 8192)

CREATE TABLE rspamd_asn (
    Date Date,
    Digest FixedString(32),
    ASN String,
    Country FixedString(2),
    IPNet String
) ENGINE = MergeTree(Date, Digest, 8192)
~~~

You can install this schema running Clickhouse CLI:

~~~
clickhouse-client --multiline
~~~

### Configuration

Example configuration shown below, minimum working configuration is `clickhouse {}`:

~~~ucl
clickhouse {
  # Push update when 1000 records are collected (1000 if unset)
  limit = 1000;
  # IP:port of Clickhouse server ("localhost:8123" if unset)
  server = "localhost:8123";
  # Timeout to wait for response (5 seconds if unset)
  timeout = 5;
  # How many bits of sending IP to mask in logs for IPv4 (19 if unset)
  ipmask = 19;
  # How many bits of sending IP to mask in logs for IPv6 (48 if unset)
  ipmask6 = 48;
  # Record URL paths? (default false)
  full_urls = false;
  # This parameter points to a map of domain names
  # If a message has a domain in this map in From: header and DKIM signature,
  # record general metadata in a table named after the domain
  #from_tables = "/etc/rspamd/clickhouse_from.map";
  # These are tables used to store data in Clickhouse
  # Table used to store ASN information (default unset: not collected)
  #asn_table = "rspamd_asn"; # default unset
  # The following table names are set by default
  # Set these if you use want to use different table names
  #table = "rspamd"; # general metadata
  #attachments_table = "rspamd_attachments"; # attachment metadata
  #urls_table = "rspamd_urls"; # url metadata
  # These are symbols of other checks in Rspamd
  # Set these if you use non-default symbol names (unlikely)
  #bayes_spam_symbols = ["BAYES_SPAM"];
  #bayes_ham_symbols = ["BAYES_HAM"];
  #fann_symbols = ["FANN_SCORE"];
  #fuzzy_symbols = ["FUZZY_DENIED"];
  #whitelist_symbols = ["WHITELIST_DKIM", "WHITELIST_SPF_DKIM", "WHITELIST_DMARC"];
  #dkim_allow_symbols = ["R_DKIM_ALLOW"];
  #dkim_reject_symbols = ["R_DKIM_REJECT"];
  #dmarc_allow_symbols = ["DMARC_POLICY_ALLOW"];
  #dmarc_reject_symbols = ["DMARC_POLICY_REJECT", "DMARC_POLICY_QUARANTINE"];
}
~~~