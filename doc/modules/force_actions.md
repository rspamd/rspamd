---
layout: doc_modules
title: Force Actions module
---

# Force Actions module

The purpose of this module is to force an action to be applied if particular symbols are matched. It is available in version 1.5.0 and greater.

# Configuration

Configuration should be added to [/etc/rspamd/rspamd.conf.local]({{ site.baseurl }}/doc/quickstart.html#configuring-rspamd).

~~~ucl
force_actions {
  # Symbols to force actions on are defined here
  actions {
    # Each action is set to a list of symbols to force the action on
    reject = ["SYMBOL_ONE", "SYMBOL_TWO"];
    "no action" = ["SYMBOL_THREE"];
    "soft reject" = ["SYMBOL_FOUR"];
    "add header" = ["SYMBOL_FIVE"];
  }
  # SMTP messages are set here
  messages {
    # If a symbol is defined here this setting is used as SMTP message
    SYMBOL_ONE = "Message is unwanted";
  }
}
~~~
