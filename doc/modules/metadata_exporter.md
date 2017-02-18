---
layout: doc_modules
title: Metadata exporter
---

# Metadata exporter

Metadata exporter selects messages of interest, extracts some information from these and pushes this information to one or more external services (Currently supported are Redis Pubsub, HTTP POST & e-Mail).

Possible applications for this include quarantines, generating alerts & feedback loops.

### Theory of operation

Metadata exporter is configured either through setting of custom Lua functions or use of library functions.

The `selector` or `select` function identifies messages that we want to export metadata from (default selector selects all messages).

The `formatter` or `format` function extracts formatted metadata from the message (default formatter returns full message content).

One or more `pushers` or the `push` function pushes formatted data to a backend.

Pusher-specific selectors and formatters can be used.

### Configuration

~~~ucl
metadata_exporter {
  # To enable a pusher from the library, add it to this list
  # and configure any required pusher-specific settings
  #pushers_enabled = ["http", "redis_pubsub", "send_mail"];
  pushers_enabled = [];

  # The pusher_format and pusher_select sections specify
  # pusher-specific format and select functions.
  pusher_format {
  #  http = "default";
  #  send_mail = "email_alert";
  }
  pusher_select {
  #  http = "default";
  #  send_mail = "is_reject_authed";
  }

  # If 'defer' is true, 'soft reject' action will be forced when message
  # could not be pushed to any backend. (default false)
  defer = false;

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
#EOD;
}
~~~

See [here]({{ site.baseurl }}/doc/configuration/redis.html) for information on configuring Redis.

### Stock pushers

 - `custom`: use custom `push` function if defined
 - `http`: sends content over HTTP POST
 - `redis_pubsub`: sends content over Redis Pubsub
 - `send_mail`: sends content over SMTP

### Stock selectors

 - `custom`: use custom `select` function if defined
 - `default`: selects all mail
 - `is_spam`: matches messages with `reject` or `add header` action
 - `is_spam_authed`: matches messages with `reject` or `add header` action from authenticated users
 - `is_reject`: matches messages with `reject` action
 - `is_reject_authed`: matches messages with `reject` action from authenticated users

### Stock formatters

 - `custom`: use custom `format` function if defined
 - `default`: returns full message content
 - `email_alert`: generates an e-Mail report about the message

### Custom functions

It is possible to define custom functions for `select`/`format`/`push` and reference these using `custom`:

~~~ucl
metadata_exporter {
  # Use custom pusher
  pushers_enabled = ["custom"];
  # Use custom selector for custom pusher
  pusher_select {
    custom = "custom";
  }
  # Use custom formatter for custom pusher
  pusher_format {
    custom = "custom";
  }
  # Define select function
  select = <<EOD
    function(task)
      -- Select all messages
      return true
    end
EOD;
  # Define custom formatter
  format = <<EOD
    function(task)
      -- Push message ID
      return task:get_message_id()
    end
EOD;
  # Define custom pusher
  push = <<EOD
    return function(task, data)
      local rspamd_logger = require "rspamd_logger"
      rspamd_logger.infox(task, 'METATEST %s', data)
    end
EOD;
}
~~~
