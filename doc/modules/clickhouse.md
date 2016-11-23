---
layout: doc_modules
title: Clickhouse module
---

# Clickhouse module

Clickhouse module pushes a variety of message-related metadata to an instance of [Clickhouse](https://clickhouse.yandex/), an open-source column-oriented DBMS useful for realtime analytics. Information that could be collected includes: senders/recipients/scores of scanned messages and metadata such as DKIM/DMARC/bayes/fuzzy status & information about URLs and attachments.

Schema is shown below:

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
  # How many bits of sending IP to mask in logs (19 if unset)
  ipmask = 19;
  # Record URL paths? (default false)
  full_urls = false;
  # This parameter points to a map of domain names
  # If a message has a domain in this map in From: header and DKIM signature,
  # record general metadata in a table named after the domain
  #from_tables = "/etc/rspamd/clickhouse_from.map";
  # These are tables used to store data in Clickhouse (defaults as shown)
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
