---
layout: doc_modules
title: Replies module
---
# Replies module

This module collects the `message-id` header of messages sent by authenticated users and stores corresponding hashes to Redis, which are set to expire after a configuable amount of time (by default 1 day). Furthermore, it hashes `in-reply-to` headers of all received messages & checks for matches (ie. messages sent in response to messages our system originated)- and yields a symbol which could be used to adjust scoring or forces an action (most likely "no action" to accept) according to configuration.


## Configuration

Settings for the module are described below (default values are indicated in brackets).

- action (null)

If set, apply the given action to messages identified as replies (would typically be set to "no action" to accept).

- expire (86400)

Time, in seconds, after which to expire records (default is one day).

- key_prefix (rr)

String prefixed to keys in Redis.

- message (Message is reply to one we originated)

Message passed when action is forced.

- servers (null)

Comma seperated list of Redis hosts

- symbol (REPLY)

Symbol yielded on messages identified as replies.

## Example

Configuration should be defined in `rspamd.conf.local`:

~~~ucl
replies {
    # This setting is non-default & is required to be set
    servers = "localhost";
    # This setting is non-default & may be desirable
    action = "no action";
    # These are default settings you may want to change
    expire = 86400;
    key_prefix = "rr";
    message = "Message is reply to one we originated";
    symbol = "REPLY";
}
~~~
