---
layout: doc_modules
title: Metadata exporter
---

# Metadata exporter

Metadata exporter selects messages of interest, extracts some information from these and pushes this information to one or more external services (Currently supported are Redis Pubsub and HTTP POST).

Possible applications for this include quarantines & feedback loops.

### Configuration

Metadata exporter is configured primarily through setting of custom Lua functions.

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
  # If set: Redis pubsub channel to use
  # channel = "foobar";
  # If set: URL to POST data to
  # url = "http://example.net/post";
  # Mime type for HTTP POST (text/plain if unset)
  # mime_type = "text/plain";
}
~~~

At least one of `channel` or `url` should be set. See [here]({{ site.baseurl }}/doc/configuration/redis.html) for information on configuring Redis.
