---
layout: doc_modules
title: Ratelimit module
---
# Ratelimit plugin

Ratelimit plugin is designed to limit messages coming from certain senders, to
certain recipients from certain IP addresses combining these parameters into
a separate limits.

All limits are stored in [Redis](http://redis.io) server (or servers cluster) to enable
shared cache between different scanners.

## Module configuration

In the default configuration, there are no cache servers specified, hence, **the module won't work** unless you add this option to the configuration.

`Ratelimit` module supports the following configuration options:

- `max_delay` - maximum lifetime for any limit bucket (1 day by default)
- `max_rcpts` - do not apply ratelimit if it contains more than this value of recipients (5 by default). This
option allows to avoid too many work for setting buckets if there are a lot of recipients in a message).
- `rates` - a table of allowed rates in form:

    type = [burst,leak];

Where `type` is one of:

- `bounce_to`
- `bounce_to_ip`
- `to`
- `to_ip`
- `to_ip_from`
- `user`

`burst` is a capacity of a bucket and `leak` is a rate in messages per second.
Both these attributes are floating point values.

- `servers` - list of servers where ratelimit data is stored; [global settings]({{ site.baseurl }}/doc/configuration/redis.html) used if not set
- `symbol` - if this option is specified, then `ratelimit` plugin just adds the corresponding symbol instead of setting pre-result, the value is scaled as $$ 2 * tanh(\frac{bucket}{threshold * 2}) $$, where `tanh` is the hyperbolic tanhent function
- `whitelisted_rcpts` - comma separated list of whitelisted recipients. By default
the value of this option is 'postmaster, mailer-daemon'
- `whitelisted_ip` - a map of ip addresses or networks whitelisted
- `whitelisted_user` - a map of usernames which are excluded from user ratelimits

## Principles of work

The basic principle of ratelimiting in Rspamd is called `leaked bucket`. It could
be visually represented as a bucket that has some capacity, and a small hole in a bottom.
Messages comes to this bucket and leak through the hole over time (it doesn't delay messages, just count them). If the capacity of
a bucket is exhausted, then a temporary reject is sent. This happens unless the capacity
of bucket is enough to accept more messages (and since messages are leaking then after some
time, it will be possible to process new messages).

Rspamd uses 3 types of limit buckets:

- `to` - a bucket based on a recipient only
- `to:ip` - a bucket combining a recipient and a sender's IP 
- `to:from:ip` - a bucket combining a recipient, a sender and a sender's IP

For bounce messages there are special buckets that lack `from` component and have more
restricted limits. Rspamd treats the following senders as bounce senders:

- 'postmaster',
- 'mailer-daemon'
- '' (empty sender)
- 'null'
- 'fetchmail-daemon'
- 'mdaemon'

Each recipient has its own triple of buckets, hence it is useful
to limit number of recipients to check.

Each bucket has two parameters:
- `capacity` - how many messages could go into a bucket before a limit is reached
- `leak` - how many messages per second are leaked from a bucket.

For example, a bucket with capacity `100` and leak `1` can accept up to 100 messages but then
will accept not more than a message per second.

By default, ratelimit module has the following settings which disable all limits:

~~~nginx
ratelimit {
  # Default settings for limits, 1st member is burst, second is rate
  rates {
    # Limit for all mail per recipient
    to = [0, 0.033333333];
    # Limit for all mail per one source ip
    to_ip = [0, 0.025];
    # Limit for all mail per one source ip and from address (rate 1 per minute)
    to_ip_from = [0, 0.01666666667];

    # Limit for all bounce mail (rate 2 per hour)
    bounce_to = [0, 0.000555556];
    # Limit for bounce mail per one source ip
    bounce_to_ip = [0, 0.000277778];

    # Limit for all mail per user (authuser) (rate 1 per minute)
    user = [0, 0.01666666667];
  }
}
~~~

### User-defined ratelimits

From 1.4.0 bucket names can be dynamically constructed - `to`, `ip`, `from`, `user`, `bounce` and `asn` (new in 1.4- requires [asn module]({{ site.baseurl }}/asn.html)) - are all keywords that can be rearranged freely joined by underscores to form new buckets, eg. `from_ip`. Furthermore the user can define their own keywords to use in construction of these buckets. Only ratelimits containing a keyword specified in the `user_keywords` setting are checked for authenticated users (by default only `user`).

To create a custom keyword, we add `custom_keywords` setting to config pointing at a Lua script which we will create:

~~~nginx
ratelimit {
   custom_keywords = "/etc/rspamd/custom_ratelimit.lua";
   # other settings ...
}
~~~

The file should return a table containing our custom function(s). For example, here is a keyword which applies ratelimits to users only when the user is found in a map:

~~~lua
local d = {}
local custom_keywords = {
  ['customuser'] = {},
}
function custom_keywords.customuser.init()
  -- create map
  d['badusers'] = rspamd_config:add_map({
    ['url']= '/etc/rspamd/badusers.map',
    ['type'] = 'set',
    ['description'] = 'Bad users'
  })
end
function custom_keywords.customuser.get_value(task)
  local user = task:get_user()
  if not user then return end -- no user, return nil
  if d['badusers']:get_key(user) then return user end -- user is in map, return user
  return -- user is not in map, return nil
end
function custom_keywords.customuser.get_limit(task)
  return {10, 0.1} -- bucket size, leak rate
end
return custom_keywords
~~~

Each keyword should define a `get_value` function which is passed the [task object](https://rspamd.com/doc/lua/task.html) and should return either a value to use in the ratelimit key or `nil` to indicate that the ratelimit should not be applied. Optionally we could also define an `init` function to perform some initialization on startup and a `condition` function which could determine wether the ratelimit is to be checked or not (typically it would make more sense to add conditions into the `get_value` function directly).

Since we want to apply the keyword to authenticated users we must add this to the `user_keywords` setting:

~~~nginx
ratelimit {
   user_keywords = ["user", "customuser"];
   # other settings ...
}
~~~

Bucket size and leak rate can be specified dynamically by creating a keyword that defines a `get_limit` function returning those fields in a table (see example above) and defining the ratelimit in `dynamic_rates` config section as shown below:

~~~nginx
ratelimit {
   dynamic_rates = {
     customuser = "customuser";
     # customuser.get_value is called for bucket name, customuser.get_limit is called for bucket size & leak rate
   }
   # other settings ...
}
~~~

### Adaptive ratelimits

From 1.4.0 Rspamd supports adaptive ratelimits- these allow for granting trusted senders increased ratelimits while reducing limits for hosts with bad or unknown reputation. This functionality requires the [ASN]({{ site.baseurl }}/asn.html) and [IP Score]({{ site.baseurl }}/ip_score.html) modules to be enabled.

To enable adaptive ratelimits, set the following:

~~~nginx
use_ip_score = true; # default false
~~~

Other settings which are of interest are:

~~~nginx
ip_score_ham_multiplier = 1.1; # default as shown
ip_score_spam_divisor = 1.1; # default as shown
~~~

These affect the extent to which limits will be increased or decreased respectively.

Ratelimits are recalculated as follows:

1) Generate a score for the particular ratelimit/sender combination between -1 and 1. If the ratelimit is of `asn` type this is calculated based on ASN reputation; If the ratelimit is of types `ip/to_ip/to_ip_from/bounce_to_ip` this is calculated based on IP reputation or, if available data is unsufficient - based on one of IPNet/ASN/country reputation (in this order), where one of these has sufficient data. If reputation is unknown the assigned score is 1.

2.1) If score is positive (reputation is bad), recalculate both size of bucket and leak rate as follows:

~~~
new_score = old_score / ip_score_spam_divisor
element = element * tanh(e * new_score)
~~~

2.2) If score is negative (reputation is good), recalculate both size of bucket and leak rate as follows:

~~~
new_score = ((1 + (old_score * -1)) * ip_score_ham_multiplier)
element = element * new_score
~~~
