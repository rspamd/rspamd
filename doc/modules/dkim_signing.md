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
