---
layout: doc_modules
title: Metadata exporter
---

# Metadata exporter

Metadata exporter selects messages of interest, extracts some information from these and pushes this information to one or more external services (Currently supported are Redis Pubsub, HTTP POST & e-Mail).

Possible applications for this include quarantines, generating alerts & feedback loops.

### Configuration

Metadata exporter is configured either through setting of custom Lua functions or use of library functions.

~~~ucl
metadata_exporter {
  # The 'select' function selects messages of interest
  # If unset all messages are selected
  select = <<EOD
    function(task)
      -- Select all messages
      return true
      -- Returns true/false: if message is of interest
    end
<<EOD;
  # If 'selector' is set it should be the name of a library function
  # to be used as the 'select' function. Possible values are described later
  # selector = "is_spam_authed";
  # This function selects the information to push
  # If unset default function shown below is used
  format = <<EOD
    function(task)
      -- Push full message content
      return task:get_content()
      -- Returns text to push to pubsub.
      -- If nil nothing is pushed.
    end
<<EOD;
  # If 'formatter' is set it should be the name of a library function
  # to be used as the 'format' function. Possible values are described later
  # formatter = "email_alert";

  # If 'defer' is true, 'soft reject' action will be forced when message
  # could not be pushed to backend. (default false)
  defer = false;

  # If 'force_action' is set, chosen action is forced on successful processing
  # force_action = "no action";

  ## Redis backend specific settings
  # Redis pubsub channel to use (no default, required)
  # channel = "foobar";

  ## HTTP backend specific settings
  # URL to post to (no default, required)
  # url = "http://example.net/post";
  # Mime type for HTTP POST (text/plain if unset)
  # mime_type = "text/plain";

  ## e-Mail backend specific settings
  # This is the SMTP server to use (no default, required)
  # smtp = "127.0.0.1";
  # This is the SMTP port to use (default 25)
  # smtp_port = 25;
  # This is the recipient of the alert (no default, required)
  # mail_to = "recipient@example.com";
  # This is the sender of the e-Mail (default empty)
  # mail_from = "sender@example.com";
  # SMTP HELO to use (default "rspamd")
  # helo = "rspamd";
  # This is the template used for the e-mail (default as shown)
  # email_template = <<EOD
#From: "Rspamd" <%s>
#To: <%s>
#Subject: Spam alert
#Date: %s
#MIME-Version: 1.0
#Message-ID: <%s>
#Content-type: text/plain; charset=us-ascii
#
#Spam received from user %s on IP %s - queue ID %s
#<<EOD;
}
~~~

At least one of `channel` or `url` or `mail_to` and `smtp` should be set. If multiple backends are configured all will be used. See [here]({{ site.baseurl }}/doc/configuration/redis.html) for information on configuring Redis.

### Stock selectors

 - `is_spam`: matches messages with `reject` or `add header` action
 - `is_spam_authed`: matches messages with `reject` or `add header` action from authenticated users
 - `is_reject`: matches messages with `reject` action
 - `is_reject_authed`: matches messages with `reject` action from authenticated users

### Stock formatters

 - `email_alert`: generates an e-Mail report about the message
