---
layout: doc_modules
title: MID module
---

# MID module

The purpose of the MID module is to suppress the `INVALID_MSGID` (malformed message-id) and `MISSING_MID` (missing message-id) rules for messages which are DKIM-signed by some particular domains.

# Configuration

The default configuration of this module is shown below:

~~~ucl
mid = {
  url = [
    "${CONFDIR}/mid.inc",
  ]; 
}
~~~

The `url` setting points to a list of maps to check DKIM signatures (& optionally message-ids) against, formatted as follows:

~~~
example.com /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}-0$/
example.net
~~~

With this configuration scoring for `INVALID_MSGID` and `MISSING_ID` symbols is removed if the domain is DKIM-signed `example.net` or the domain is signed `example.com` and the message-id matches the specified regex.
