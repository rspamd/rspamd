---
layout: doc_modules
title: Rmilter headers module
---

# Rmilter headers module

The Rmilter headers module has been added in Rspamd 1.5 to provide a relatively simple way to configure adding/removing of headers via Rmilter (the alternative being to use the [API]({{ site.baseurl }}/doc/lua/task.html#me7351)). Despite its namesake it also works with [Haraka](https://haraka.github.io).

# Principles of operation

The Rmilter headers module provides a number of routines to add common headers which can be enabled and configured individually. User-defined routines can also be added to configuration.

# Configuration

~~~ucl
rmilter_headers {
  # routines to use
  use = ["x-spamd-bar", "authentication-results", "my_routine"];
  routines {
    # settings for x-spamd-bar routine
    x-spamd-bar {
      # effectively disables negative spambar
      negative = "";
    }
  }
  # custom routines
  custom {
    my_routine = <<EOD
return function(task, common_meta)
  local add, remove, common = {}, {}, {}
  local do_stuff = false
  if common_meta.symbols then
    if common_meta.symbols.R_SPF_ALLOW == false then
      # Previous routine recorded R_SPF_ALLOW not present
      return
    elseif common_meta.symbols.R_SPF_ALLOW then
      # Previous routine recorded R_SPF_ALLOW present
      do_stuff = true
      add['SPF-Pass'] = 'true'
      remove['SPF-Pass'] = 1
    else
      local sym = task:get_symbol('R_SPF_ALLOW')
      common.symbols = {}
      if sym then
        do_stuff = true
        common.symbols.R_SPF_ALLOW = sym
      else
        common.symbols.R_SPF_ALLOW = false
      end
    end
    if do_stuff then
      add['SPF-Pass'] = 'true'
      remove['SPF-Pass'] = 1
    end
  end
  # Return error (or nil); headers to add; headers to remove; metadata to store
  return nil, add, remove, common
EOD; 
  }
}
~~~

# Functions

Available routines and their settings are as below, default values are as indicated:

## authentication-results

Add an [authentication-results](https://tools.ietf.org/html/rfc7001) header.

~~~ucl
  # Name of header
  header = 'Authentication-Results';
  # Remove existing headers
  remove = 1;
  # SPF/DKIM/DMARC symbols in case these are redefined
  spf_symbols {
    pass = "R_SPF_ALLOW";
    fail = "R_SPF_FAIL";
    softfail = "R_SPF_SOFTFAIL";
    neutral = "R_SPF_NEUTRAL";
    temperror = "R_SPF_DNSFAIL";
    none = "R_SPF_NA";
    permerror = "R_SPF_PERMFAIL";
  }
  dkim_symbols {
    pass = "R_DKIM_ALLOW";
    fail = "R_DKIM_REJECT";
    temperror = "R_DKIM_TEMPFAIL";
    none = "R_DKIM_NA";
    permerror = "R_DKIM_PERMFAIL";
  }
  dmarc_symbols {
    pass = "DMARC_POLICY_ALLOW";
    permerror = "DMARC_BAD_POLICY";
    temperror = "DMARC_DNSFAIL";
    none = "DMARC_NA";
    reject = "DMARC_POLICY_REJECT";
    softfail = "DMARC_POLICY_SOFTFAIL";
    quarantine = "DMARC_POLICY_QUARANTINE";
  }
~~~

## spam-header

Adds a predefined header to mail identified as spam.

~~~ucl
  header = "Deliver-To";
  value = "Junk";
  remove = 1;
~~~

Default name/value of the added header is `Deliver-To`/`Junk` which can be manipulated using the `header` and `value` settings.

## x-spamd-bar

Adds a visual indicator of spam/ham level.

~~~ucl
  header = "X-Spamd-Bar";
  positive = "+";
  negative = "-";
  neutral = "/";
  remove = 1;
~~~

## x-spam-level

Another visual indicator of spam level- SpamAssassin style.

~~~ucl
  header = "X-Spam-Level";
  char = "*";
  remove = 1;
~~~

## x-spam-status

SpamAssassin-style X-Spam-Status header indicating spam status.

~~~ucl
  header = "X-Spam-Status";
  remove = 1;
~~~

## x-virus

~~~ucl
  header = "X-Virus";
  remove = 1;
  # The following setting is an empty list by default and required to be set
  # These are user-defined symbols added by the antivirus module
  symbols = ["CLAM_VIRUS", "FPROT_VIRUS"];
~~~

Adds a header containing names of virii detected by scanners configured in [Antivirus module]({{ site.baseurl }}/doc/modules/antivirus.html) in case that virii are detected in a message.
