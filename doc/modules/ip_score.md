---
layout: doc_modules
title: IP Score module
---

# IP Score

IP Score stores records in Redis - [see here]({{ site.baseurl }}/doc/configuration/redis.html) for information about configuring Redis.

Since Rspamd 1.3.4, IP Score requires lookup information from [ASN module]({{ site.baseurl }}/doc/modules/asn.html).

### Theory of operation

IP Score tracks the number of messages received from a given IP/subnet/ASN/country and records this alongside a total score. The scores which are added to these total scores are calculated as follows:

~~~
ip_score = action_multiplier * tanh (e * (metric_score/score_divisor))
~~~

`e` is the mathematical constant: 2.718.
`tanh` is the hyperbolic tangent function.
`metric_score` is the score Rspamd assigned the message.
`action_multiplier` is the multiplier configured for the metric action, or zero in case action is `no action` and score is positive.
`score_divisor` is supplied from setting with the same name- if not supplied no divison is done (recommended value: 10-100).

Default multipliers are shown below:

~~~ucl
	actions {
		reject = 1.0;
		"add header" = 0.25;
		"rewrite subject" = 0.25;
		"no action" = 1.0;
	}
~~~

So with these settings:

- a message with score -0.1 gets ip score: -0.265
- a message with score -1.0 gets ip score: -0.991
- a message with positive score & `no action` action always gets ip score: 0.00
- a message with `add header` action & score 7 gets ip score: 0.249
- a message with `reject` action and score 15 gets ip score: 1.0

For each IP address/ASN/country/subnet Rspamd stores a key in a hash in Redis the value of which is formatted: `total ip score|total number of messages received` - for each incoming message Rspamd increments the total number of messages by one and adds the new ip score to the total.

Once a predefined number of messages from a given IP address/subnet/ASN/country have been seen (10 in default configuration), Rspamd will begin to add scores to messages, which are calculated as follows:

First Rspamd calculates a subscore for whichever things it has seen enough messages for (IP address/subnet/ASN/country) as follows:

~~~
subscore = score_multiplier * tanh(e * total_score / total_messages)
subscore = floor(subscore * 10)
~~~

Score multiplier is dependent on the component the subscore is being generated for; default multipliers are shown below:

~~~ucl
	scores {
		asn = 0.5;
		country = 0.1;
		ipnet = 0.8;
		ip = 1.0;
	}
~~~

Subscores are added to each other to determine a total. If `min_score` or `max_score` are defined in configuration these set a lower/upper bound for the total score.

### Configuration

Refer to example configuration below for available settings. To use default settings, [configure Redis]({{ site.baseurl }}/doc/configuration/redis.html) globally and add `ip_score { }` to `/etc/rspamd/rspamd.conf.local`.

~~~ucl
ip_score {
	# how each action is treated in scoring
	actions {
		reject = 1.0;
		"add header" = 0.25;
		"rewrite subject" = 0.25;
		"no action" = 1.0;
	}
	# how each component is evaluated
	scores {
		asn = 0.5;
		country = 0.1;
		ipnet = 0.8;
		ip = 1.0;
	}
	# prefix for asn hashes
	asn_prefix = "a:";
	# prefix for country hashes
	country_prefix = "c:";
	# hash table in redis used for storing scores
	hash = "ip_score";
	# prefix for subnet hashes
	ipnet_prefix = "n:";
	# minimum number of messages to be scored
	lower_bound = 10;
	# the metric to score (usually "default")
	metric = "default";
	# upper and lower bounds at which to cap total score
	#max_score = 10;
	#min_score = -5;
	# Amount to divide subscores by before applying tanh
	score_divisor = 10;
	# list of servers (or configure redis globally)
	#servers = "localhost";
	# symbol to be inserted
	symbol = "IP_SCORE";
}
~~~

You will also have to register some weight for the symbol in metric. For example you could add the following to `local.d/metrics.conf`:

~~~ucl
symbol "IP_SCORE" {
	weight = 2.0;
	description = "IP reputation";
}
~~~
