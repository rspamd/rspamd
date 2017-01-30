---
layout: doc_modules
title: DKIM signing module
---

# DKIM signing module

The DKIM signing module has been added in Rspamd 1.5 to provide a relatively simple way to configure DKIM signing, the more flexible alternative being [sign_condition]({{ site.baseurl }}/doc/modules/dkim.html#dkim-signatures) in the DKIM module.

# Principles of operation

The DKIM signing module chooses signing domains and selectors according to a predefined policy which can be modified with various settings. Description of this policy follows:

 * To be eligible for signing, a mail must be received from an authenticated user OR a reserved IP address OR an address in the `sign_networks` map (if defined)
 * If envelope from address is not empty, the effective second level domain must match the MIME header From
 * If authenticated user is present, this should be suffixed with @domain where domain is what's seen is envelope/header From address
 * Selector and path to key are selected from domain-specific config if present, falling back to global config

# Configuration

~~~ucl
dkim_signing {
  # If false, messages with empty envelope from are not signed
  allow_envfrom_empty = true;
  # If true, envelope/header domain mismatch is ignored
  allow_hdrfrom_mismatch = false;
  # If true, multiple from headers are allowed (but only first is used)
  allow_hdrfrom_multiple = false;
  # If true, username does not need to contain matching domain
  allow_username_mismatch = false;
  # If false, messages from authenticated users are not selected for signing
  auth_only = true;
  # Default path to key, can include '$domain' and '$selector' variables
  path = "/var/lib/rspamd/dkim/$domain.$selector.key";
  # Default selector to use
  selector = "dkim";
  # If false, messages from local networks are not selected for signing
  sign_local = true;
  # Symbol to add when message is signed
  symbol = "DKIM_SIGNED";
  # Whether to fallback to global config
  try_fallback = true;
  # Domain to use for DKIM signing: can be "header" or "envelope"
  use_domain = "header";
  # Whether to normalise domains to eSLD
  use_esld = true;
  # Whether to get keys from Redis
  use_redis = false;
  # Hash for DKIM keys in Redis
  hash_key = "DKIM_KEYS";

  # Domain specific settings
  domain {
    example.com {
      # Private key path
      path = "/var/lib/rspamd/dkim/example.key";
      # Selector
      selector = "ds";
    }
  }
} 
~~~

## DKIM keys in Redis

To use DKIM keys stored in Redis you should add the following to configuration:

~~~ucl
dkim_signing {
  use_redis = true;
  hash_key = "DKIM_KEYS";
  selector = "myselector";
}
~~~

... and populate the named hash with DKIM keys; for example the following Lua script could be run with `redis-cli --eval`:

~~~lua
local key = [[-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANe3EETkiI1Exyrb
+VzbMSt90K8MXJA0GcyNs6MFCs9JPaTh90Zu2l7ki7m5LTUx6350AR/3hcvwjSHC
ZjD6fvQ8/zfjN8kaLZ6DAaqtqSlpawIM+8glkuTEkIkpBED/OtDrba4Rd29iLFVu
wQZXDtTjAAZKZPmtTZ5TXLrcCU6VAgMBAAECgYEA1BFvmBsIN8Gu/+6kNupya2xU
NVM0yLu/xT5lpNV3LBO325oejAq8+d87kkl/LTW3a2jGFlQ0ICuLw+2mo24QUWRy
v8if3oeBMlnLqHE+6wNjFVqo5sOjKzjO363xSXwXNUrBT7jDhnZcDN8w3/FecYKj
ifGTVtUs1SLsYwhlc8ECQQDuCRymLZQ/imPn5eFVIydwUzg8ptZlvoA7bfIxUL9B
QRX33s59kLCilA0tTed8Dd+GnxsT93XOj1ApIfBwmTSlAkEA5/63PDsN7fH+WInq
VD8nU07M9S8LcGDlPbVVBr2S2I78/iwrSDAYtbkU2vEbhFK/JuKNML2j8OkzV3v1
QulfMQJBALDzhx+l/HHr3+8RPhx7QKNIyiKUaAdEwbDsP8IXY8YPq1QThu9jM1v4
sX7/TdkzuvoppwiFykbe1NlvCH279p0CQCmTg4Ee0DtBcCSr6rvYaZLLf329RZ6J
LuwlMCy6ErQOxBZFEiiovfTrS2qFZToMnkc4uLbwdY36LQJTq7unGTECQCCok8Lz
BeZtAw+TJofpOM3F2Rlm2qXiBVBeubhRedsiljG0hpvvLJBMppnQ6r27p5Jk39Sm
aTRkxEKrxPWWLNM=
-----END PRIVATE KEY-----]]
redis.call('HMSET', 'DKIM_KEYS', 'myselector.example.com', key)
~~~

The selector will be chosen as per usual (a domain-specific selector will be used if configured, otherwise the global setting is used).
