# Rspamd metrics settings

## Introduction

Metrics section provides configuration for symbols weights and actions apllied for a message by rspamd.
You could imagine metric as a decision used by rspamd for a specific message by a set of
rules. Each rule can insert a `symbol` to the metric, that means that this rule is true
for this message. Each symbol can have a floating point value called `weight` that means
the significance of the correspoinding rule. Rules with positive weight icrease `spam` like
property whilst rules with negative weight increase `ham` like property. The final estimation
is the messages's score.

After a score is evaluated, rspamd selects an appropriate `action` for a message. Action
means the desired operation that should be applied for a message based on the specific
metric. Rspamd defines the following actions ordered by `spam like` property in ascending
order:

1. `no action` - a message is likely ham
2. `greylist` - a message should be greylisted to ensure sender's validity
3. `add header` - add the specific `spam` header indicating that a message is likely spam
4. `rewrite subject` - add spam subject to a message
5. `soft reject` - temporary reject a message
6. `reject` - permamently reject a message

Actions are assumed to be applied simultaneously, meaning that `add header` action implies,
for example, `greylist` action. `add header` and `rewrite subject` have actually the same
power in terms of rspamd. They are just two options of the same purpose: to mark a message
as probable spam. `soft reject` action is mainly used to indicate temporary issues in mail
delivery, for instance, rate limit reaching.

There is also special purpose metric called as `default` that acts as the main metric
to treat a message as spam or ham. Actually, all clients that use rspamd just check the
default metric to determine whether a message is spam or ham. Therefore, the distribution
configuration defines merely the `default` metric.

## Configuring metrics
Each metric is defined by a `metric` object in rspamd configuration. This object has one
mandatory attribute - `name` which defines the name of this metric:

~~~nginx
metric {
   # Define default metric
   name = "default";
}
~~~
It is also possible to define some generic attributes for the metric:

* `grow_factor` - the multiplicator applied for the subsequent symbols inserting by the follwing rule:

$$
score = score + grow\_factor * symbol\_weight
$$

$$
	grow\_factor = grow\_factor * grow\_factor
$$

by default this value is `1.0` meaning that no weight growing is defined. By increasing this value you
increase the efficient score of messages with multiple `spam` rules matched. This value
is not affected by negative score values.

* `subject` - string value that is prepended to the messages's subject if `rewrite subject`
action is applied
* `unknown_weight` - weight for unknown rules. If this parameter is specified, then all rules can
insert symbols to this metric. If such a rule is not specified by this metric then its weight is equal
to this option's value. Please note, that adding this option means that all rules will be checked by rspamd, on the
contrary, if no `unknown_weight` metric is specified then rules that are not registered anywhere are silently ignored
by rspamd.


The content of this section is separated to the two main parts: symbols and actions.
Actions section is an object of all actions defined by this metric. If some actions are skipped,
they won't be ever suggested by rspamd. Actions section looks as following:

~~~nginx
metric {
...
	actions {
		reject = 15;
		add_header = 6;
		greylist = 4;
	};
...
}
~~~

You can use `_` symbol instead of space in action names to simplify the configuration.

Symbols are defined by an object with the following properties:

* `weight` - the symbol weight as floating point number (negative or positive), by default the weight is `1.0`
* `name` - symbolic name for a symbol (mandatory attribute)
* `group` - a group of symbol, for example `DNSBL symbols` (as shown in webui)
* `description` - optional symbolic description for webui
* `one_shot` - normally, rspamd inserts a symbol as much time as the corresponding rule mathes for the specific message, however, if `one_shot` is `true` then only **maximum** weight is added to the metric. `grow_factor` is correspondingly not modified by a repeated triggering of `one_shot` rules.

So far, the symbol definition looks like this one:

~~~nginx
symbol { 
    name = "RWL_SPAMHAUS_WL_IND"; 
    weight = -0.7; 
    description = "Sender listed at Spamhaus whitelist"; 
}
~~~

A single metric can contain multiple symbols definitions.


## Symbol groups

Symbols can be grouped to specify their common functionality. For example, one might group all
`RBL` symbols all together. Moreover, from rspamd 0.9 it is possible to specify group score limit,
which could be useful, for instance if some specific group should not unconditionally send a message
to `spam` class. Here is an example of such a functionality:

~~~nginx
metric {
	name = default;
	
	group {
		name = "RBL group";
		max_score = 6.0;
		
		symbol {
			name = "RBL1";
			weight = 1;
		}
		symbol {
			name = "RBL2";
			weight = 4;
		}
		symbol {
			name = "RBL3";
			weight = 5;
		}
	}
}
~~~