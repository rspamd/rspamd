# rspamd metrics settings

## Introduction

The metrics section configures weights for symbols and actions applied to a message by rspamd. You can imagine a metric as a decision made by rspamd for a specific message by a set of rules. Each rule can insert a `symbol` into the metric, which means that this rule is true for this message. Each symbol can have a floating point value called a `weight`, which means the significance of the corresponding rule. Rules with a positive weight increase the spam factor, while rules with negative weights increase the ham factor. The result is the overall message score.

After a score is evaluated, rspamd selects an appropriate `action` for a message. rspamd defines the following actions, ordered by spam factor, in ascending order:

1. `no action` - a message is likely ham
2. `greylist` - a message should be greylisted to ensure sender's validity
3. `add header` - add the specific `spam` header indicating that a message is likely spam
4. `rewrite subject` - add spam subject to a message
5. `soft reject` - temporarily reject a message
6. `reject` - permanently reject a message

Actions are assumed to be applied simultaneously, meaning that the `add header` action implies, for example, the `greylist` action. `add header` and `rewrite subject` are equivalent to rspamd. They are just two options with the same purpose: to mark a message as probable spam. The `soft reject` action is mainly used to indicate temporary issues in mail delivery, for instance, exceeding a rate limit.

There is also a special purpose metric called `default` that acts as the main metric to treat a message as spam or ham. Actually, all clients that use rspamd just check the default metric to determine whether a message is spam or ham. Therefore, the default configuration just defines the `default` metric.

## Configuring metrics
Each metric is defined by a `metric` object in the rspamd configuration file. This object has one mandatory attribute - `name` - which defines the name of the metric:

~~~ucl
metric {
   # Define default metric
   name = "default";
}
~~~
It is also possible to define some generic attributes for the metric:

* `grow_factor` - the multiplier applied for the subsequent symbols inserting by the following rule:

$$
score = score + grow\_factor * symbol\_weight
$$

$$
	grow\_factor = grow\_factor * grow\_factor
$$

By default this value is `1.0` meaning that no weight growing is defined. By increasing this value you increase the effective score of messages with multiple `spam` rules matched. This value is not affected by negative score values.

* `subject` - string value that is prepended to the message's subject if the `rewrite subject` action is applied
* `unknown_weight` - weight for unknown rules. If this parameter is specified, all rules can add symbols to this metric. If such a rule is not specified by this metric then its weight is equal to this option's value. Please note, that adding this option means that all rules will be checked by rspamd, on the contrary, if no `unknown_weight` metric is specified then rules that are not registered anywhere are silently ignored by rspamd.

The content of this section is in two parts: symbols and actions. Actions is an object of all actions defined by this metric. If some actions are skipped, they won't be ever suggested by rspamd. The Actions section looks as follows:

~~~ucl
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

You can use an underscore (`_`) instead of white space in action names to simplify the configuration.

Symbols are defined by an object with the following properties:

* `weight` - the symbol weight as floating point number (negative or positive); by default the weight is `1.0`
* `name` - symbolic name for a symbol (mandatory attribute)
* `group` - a group of symbols, for example `DNSBL symbols` (as shown in WebUI)
* `description` - optional symbolic description for WebUI
* `one_shot` - normally, rspamd inserts a symbol as many times as the corresponding rule matches for the specific message; however, if `one_shot` is `true` then only the **maximum** weight is added to the metric. `grow_factor` is correspondingly not modified by a repeated triggering of `one_shot` rules.

A symbol definition can look like this:

~~~ucl
symbol {
    name = "RWL_SPAMHAUS_WL_IND";
    weight = -0.7;
    description = "Sender listed at Spamhaus whitelist";
}
~~~

A single metric can contain multiple symbols definitions.


## Symbol groups

Symbols can be grouped to specify their common functionality. For example, one could group all `RBL` symbols together. Moreover, from rspamd version 0.9 it is possible to specify a group score limit, which could be useful, for instance, if a specific group should not unconditionally send a message to the `spam` class. Here is an example of such a functionality:

~~~ucl
metric {
	name = default; # This is mandatory option
	
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
