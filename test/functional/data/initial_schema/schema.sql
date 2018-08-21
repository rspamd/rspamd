CREATE TABLE IF NOT EXISTS rspamd
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
    Action Enum8('reject' = 0, 'rewrite subject' = 1, 'add header' = 2, 'greylist' = 3, 'no action' = 4, 'soft reject' = 5) DEFAULT CAST('no action' AS Enum8('reject' = 0, 'rewrite subject' = 1, 'add header' = 2, 'greylist' = 3, 'no action' = 4, 'soft reject' = 5)),
    FromUser String,
    MimeUser String,
    RcptUser String,
    RcptDomain String,
    ListId String,
    Digest FixedString(32)
) ENGINE = MergeTree(Date, (TS, From), 8192);


CREATE TABLE IF NOT EXISTS rspamd_attachments (
    Date Date,
    Digest FixedString(32),
    `Attachments.FileName` Array(String),
    `Attachments.ContentType` Array(String),
    `Attachments.Length` Array(UInt32),
    `Attachments.Digest` Array(FixedString(16))
) ENGINE = MergeTree(Date, Digest, 8192);


CREATE TABLE IF NOT EXISTS rspamd_urls (
    Date Date,
    Digest FixedString(32),
    `Urls.Tld` Array(String),
    `Urls.Url` Array(String)
) ENGINE = MergeTree(Date, Digest, 8192);


CREATE TABLE IF NOT EXISTS rspamd_emails (
    Date Date,
    Digest FixedString(32),
    Emails Array(String)
) ENGINE = MergeTree(Date, Digest, 8192);


CREATE TABLE IF NOT EXISTS rspamd_asn (
    Date Date,
    Digest FixedString(32),
    ASN String,
    Country FixedString(2),
    IPNet String
) ENGINE = MergeTree(Date, Digest, 8192);


CREATE TABLE IF NOT EXISTS rspamd_symbols (
    Date Date,
    Digest FixedString(32),
    `Symbols.Names` Array(String),
    `Symbols.Scores` Array(Float64),
    `Symbols.Options` Array(String)
) ENGINE = MergeTree(Date, Digest, 8192);


