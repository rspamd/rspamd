---
layout: doc_modules
title: Rmilter headers module
---

# Rmilter headers module

The Rmilter headers module has been added in Rspamd 1.5 to provide a relatively simple way to configure adding/removing of headers via Rmilter (the alternative being to use the [API]({{ site.baseurl }}/doc/lua/task.html#me7351)). Despite its namesake it also works with [Haraka](https://haraka.github.io).

# Principles of operation

The Rmilter headers module provides a number of routines to add common headers which can be selectively enabled and configured. User-defined routines can also be added to configuration.

# Configuration

~~~ucl
rmilter_headers {
  # routines to use- this is the only required setting
  use = ["x-spamd-bar", "authentication-results"];
  # this is where we may configure our selected routines
  routines {
    # settings for x-spamd-bar routine
    x-spamd-bar {
      # effectively disables negative spambar
      negative = "";
    }
    # other routines...
  }
  custom {
    # user-defined routines: more on these later
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

# Custom routines

User-defined routines can be defined in configuration in the `custom` section, for example:

~~~ucl
  custom {
    my_routine = <<EOD
return function(task, common_meta)
  -- parameters are task and metadata from previous functions
  return nil, -- no error
    {['X-Foo'] = 'Bar'}, -- add header: X-Foo: Bar
    {['X-Foo'] = 1}, -- remove foreign X-Foo headers
    {}, -- metadata to return to other functions
EOD;
  }
~~~

The key `my_routine` could then be referenced in the `use` setting like other routines.
