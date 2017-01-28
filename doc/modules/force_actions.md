---
layout: doc_modules
title: Force Actions module
---

# Force Actions module

The purpose of this module is to force an action to be applied if particular symbols are found/not found and optionally return a specified SMTP message. It is available in version 1.5.0 and greater.

# Configuration

Configuration should be added to [/etc/rspamd/rspamd.conf.local](({{ site.baseurl }}/doc/quickstart.html#configuring-rspamd).

~~~ucl
force_actions {
  # Symbols to force actions on are defined here
  actions {
    # Each action is set to a list of symbols to force the action on
    reject = ["SYMBOL_ONE", "SYMBOL_TWO"];
    # Nested lists include SMTP response messages
    "soft reject" = [ ["SYMBOL_FOUR", "Please try later"], "SYMBOL_SIX"];
    # Expressions are supported in addition to plain symbols
    "no action" = ["IS_WHITELISTED & !CLAM_VIRUS & !FPROT_VIRUS)"];
    "add header" = ["SYMBOL_FIVE"];
  }
  # SMTP messages could be set here
  messages {
    # If a symbol/expression is defined here and no nested SMTP message was configured
    # then this setting is used as SMTP message
    "SYMBOL_ONE" = "Message is unwanted";
  }
}
~~~
