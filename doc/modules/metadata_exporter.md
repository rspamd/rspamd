---
layout: doc_modules
title: Metadata exporter
---

# Metadata exporter

Metadata exporter processes a set of rules which identify interesting messages & and push information based on these to an external service (Currently supported are Redis Pubsub, HTTP POST & SMTP; user-defined backends can also be used).

Possible applications include quarantines, logging, alerting & feedback loops.

### Theory of operation

For each rule defined in configuration:

 - A `selector` function identifies messages that we want to export metadata from (default selector selects all messages).
 - A `formatter` function extracts formatted metadata from the message (default formatter returns full message content).
 - A `pusher` function (defined by the `backend` setting) pushes the formatted metadata somewhere

A number of such functions are defined in the plugin which can be used in addition to user-defined functions.

### Configuration

~~~ucl
metadata_exporter {

  # Each rule defines some export process

  rules {

    # The following rule posts JSON-formatted metadata at the defined URL
    # when it sees a rejected mail from an authenticated user
    MY_HTTP_ALERT_1 {
      backend = "http";
      url = "http://127.0.0.1:8080/foo";
      # More about selectors and formatters later
      selector = "is_reject_authed";
      formatter = "json";
    }

    # This rule posts all messages to a Redis pubsub channel
    MY_REDIS_PUBSUB_1 {
      backend = "redis_pubsub";
      channel = "foo";
      # Defalt formatter and selector is used
    }

    # This rule sends an e-Mail alert over SMTP containing message metadata
    # when it sees a rejected mail from an authenticated user
    MY_EMAIL_1 {
      backend = "send_mail";
      smtp = "127.0.0.1";
      mail_to = "user@example.com";
      selector = "is_reject_authed";
      formatter = "email_alert";
    }

  }

}
~~~

### Stock pushers (backends)

 - `http`: sends content over HTTP POST
 - `redis_pubsub`: sends content over Redis Pubsub
 - `send_mail`: sends content over SMTP

### Stock selectors

 - `default`: selects all mail
 - `is_spam`: matches messages with `reject` or `add header` action
 - `is_spam_authed`: matches messages with `reject` or `add header` action from authenticated users
 - `is_reject`: matches messages with `reject` action
 - `is_reject_authed`: matches messages with `reject` action from authenticated users

### Stock formatters

 - `default`: returns full message content
 - `email_alert`: generates an e-Mail report about the message
 - `json`: returns json-formatted metadata about a message

### Settings: general

The following settings can be defined on any rule:

 - `selector`: defines selector for the rule
 - `formatter`: defines formatter for the rule
 - `backend`: defines backend (pusher) for the rule
 - `defer`: if true, `soft reject` action is forced on failed processing

### Settings: `http` backend

 - `url` (required): defines URL to post content to
 - `meta_header_prefix`: prefix for meta headers (default 'X-Rspamd-')
 - `meta_headers`: if set true general metainformation is added to HTTP request headers (default false)
 - `mime_type`: defines mime type of content sent in HTTP POST

### Settings: `redis_pubsub` backend

 - `channel` (required): defines pubsub channel to post content to

See [here]({{ site.baseurl }}/doc/configuration/redis.html) for information on configuring Redis servers.

### Settings: `send_mail` backend

 - `smtp` (required): hostname of SMTP server
 - `mail_to` (required): recipient of e-mail alert
 - `mail_from`: Sender address (default empty)
 - `helo`: HELO to send (default 'rspamd')
 - `smtp_port`: SMTP port if not 25
 - `email_template`: template used for alert (default shown below):

~~~
From: "Rspamd" <$mail_from>
To: <$mail_to>
Subject: Spam alert
Date: $date
MIME-Version: 1.0
Message-ID: <$our_message_id>
Content-type: text/plain; charset=us-ascii

Authenticated username: $user
IP: $ip
Queue ID: $qid
SMTP FROM: $from
SMTP RCPT: $rcpt
MIME From: $header_from
MIME To: $header_to
MIME Date: $header_date
Subject: $header_subject
Message-ID: $message_id
Action: $action
Symbols: $symbols
~~~

Variables can be substituted according to general metadata keys described in the next section.

### General metadata

Metadata as returned by the `json` formatter can be referenced by key in `email_template`. The following keys are defined:

- `action`: metric action for message
- `from`: SMTP FROM
- `header_date`: Contents of Date header(s)
- `header_from`: Contents of From header(s)
- `header_subject`: Contents of Subject header(s)
- `header_to`: Contents of To header(s)
- `ip`: IP of message sender
- `mail_from` (`email_template` only): sender of alert
- `mail_to` (`email_template` only): recipient of alert
- `message_id`: Message-ID of original message
- `our_message_id` (`email_template` only): message-ID generated for alert
- `qid`: Queue-ID of message provided by MTA
- `rcpt`: SMTP RCPT
- `score`: Metric score of the message
- `symbols`: Symbols in metric
- `user`: authenticated username of message sender

### Custom functions

It is possible to define custom selectors/pushers/backends. Functions are defined in the `custom_select`/`custom_format`/`custom_push` groups and referenced by name in the `selector`/`formatter`/`backend` settings:

~~~ucl
metadata_exporter {

  # Define custom selector(s)
  custom_select {
    mine = <<EOD
return function(task)
  -- Select all messages
  return true
end
EOD;
  }

  # Define custom formatter(s)
  custom_format {
    mine = <<EOD
return function(task)
  -- Push message ID
  return task:get_message_id()
end
EOD;
  }

  # Define custom backend(s)
  custom_push {
    mine = <<EOD
return function (task, data, rule)
  -- Log payload
  local rspamd_logger = require "rspamd_logger"
  rspamd_logger.infox(task, 'METATEST %s', data)
end
EOD;
  }

  rules {

    CUSTOM_EXPORT {
      selector = "mine";
      formatter = "mine";
      backend = "mine";
    }

  }

}
~~~
