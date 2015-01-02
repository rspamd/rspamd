# Fuzzy check module

This module is intended to check messages for specific fuzzy patterns stored in
[fuzzy storage workers](../workers/fuzzy_storage.md). At the same time, this module
is responsible for learning fuzzy storage with message patterns.

## Fuzzy patterns

Rspamd uses `shingles` algorithm to perform fuzzy match of messages. This algorithm
is probabilistic and uses words chains to detect some common patterns and filter
thus spam or ham messages. Shingles algorithm is described in the following 
[research paper](http://dl.acm.org/citation.cfm?id=283370). We use 3-gramms for this
algorithm and [siphash](https://131002.net/siphash/) for hash function. Currently,
rspamd uses 32 hashes for shingles. Using of siphash allows private storages to be
used, since nobody can generate the same sequence of hashes without some shared
secret called `shingles key`. By default, rspamd uses the string `rspamd` as siphash
key, however, it is possible change this value from the configuration.

Each shingles set is accompanied by a collision resistant hash, namely [blake2](https://blake2.net/) hash.
This digest is used as unique ID of the hash.

Attachements and images are not currently matched against fuzzy hashes, however they
are checked by means blake2 digests using strict match.

## Module configuration

Fuzzy check module has several global options and allows to specify multiple match
storages. Global options include:

- `symbol`: default symbol to insert (if no flags matches)
- `min_length`: minimum length of text parts in words to perform fuzzy check (default - check all text parts)
- `min_bytes`: minimum lenght of attachements and images in bytes to check them in fuzzy storage
- `whitelist`: IP list to skip all fuzzy checks
- `timeout`: timeout for reply waiting

Fuzzy rules are defined as a set of `rule` definitions. Each `rule` must have servers
list to check or learn and a set of flags and optional parameters. Here is an example of
rule's settings:

~~~nginx
fuzzy_check {
	rule {
		# List of servers, can be an array or multi-value item
		servers = "localhost:11335";
		servers = "highsecure.ru:11335";

		# Default symbol
		symbol = "FUZZY_UNKNOWN";

		# List of additional mime types to be checked in this fuzzy
		mime_types = "application/pdf";

		# Maximum global score for all maps
		max_score = 20.0;

		# Ignore flags that are not listed in maps for this rule
		skip_unknown = yes;

		# If this value is false, then allow learning for this fuzzy rule
		read_only = no;

		# Key for strict digests (default: "rspamd")
		fuzzy_key = "somebigrandomstring";

		# Key for fuzzy siphash (default: "rspamd")
		fuzzy_shingles_key = "anotherbigrandomstring";

		# maps
	}
}
~~~

Each rule can have several maps defined by a `flag` value. For example, a single
fuzzy storage can contain both good and bad hashes that should have different symbols
and thus different weights. Maps are defined inside fuzzy rules as following:

~~~nginx
fuzzy_check {
	rule {
	...
	fuzzy_map = {
		FUZZY_DENIED {
			# Maximum weight for this list
			max_score = 20.0;
			# Flag value
			flag = 1
        }
        FUZZY_PROB {
			max_score = 10.0;
			flag = 2
        }
        FUZZY_WHITE {
			max_score = 2.0;
			flag = 3
        }
	}
}
~~~

The meaning of `max_score` can be rather unclear. First of all, all hashes in
fuzzy storage have their own weights. For example, if we have a hash `A` and 100 users
marked it as spam hash, then it will have weight of `100 * single_vote_weight`.
Therefore, if a `single_vote_weight` is `1` then the final weight will be `100` indeed.
`max_score` means the weight that is required for the rule to add symbol with the maximum
score 1.0 (that will be of course multiplied by metric's weigth). In our example,
if the weight of hash is `100` and `max_score` will be `99`, then the rule will be
added with the weight of `1`. If `max_score` is `200`, then the rule will be added with the
weight likely `0.2` (the real function is hyperbolic tangent). In the following configuration:

~~~nginx
metric {
	name = "default";
	...
	symbol {
		name = "FUZZY_DENIED";
		weght = "10.0";
	}
	...
}
fuzzy_check {
	rule {
	...
	fuzzy_map = {
		FUZZY_DENIED {
			# Maximum weight for this list
			max_score = 20.0;
			# Flag value
			flag = 1
        }
        ...
    }
}
~~~

If a hash has value `10`, then a symbol `FUZZY_DENIED` with weight of `2.0` will be added.
If a hash has value `100500`, then `FUZZY_DENIED` will have weight `10.0`.

## Learning for fuzzy_check

Module `fuzzy_check` also allows to learn messages. You can use `rspamc` command or
connect to the **controller** worker using HTTP protocol. For learning you must check 
the following settings:

1. Controller worker should be accessible by `rspamc` or HTTP (check `bind_socket`)
2. Controller should allow privilleged commands for this client (check `enable_password` or `allow_ip` settings)
3. Controller should have `fuzzy_check` module configured to the servers specified
4. You should know `fuzzy_key` and `fuzzy_shingles_key` to operate with this storage
5. Your `fuzzy_check` module should have `fuzzy_map` configured to the flags used by server
6. Your `fuzzy_check` rule must have `read_only` option being turned off - `read_only = false`
7. Your `fuzzy_storage` worker should allow updates from the controller's host (`allow_update` option)
8. Your controller should be able to communicate with fuzzy storage by means of `UDP` protocol

If all these conditions are met then you can learn messages with rspamc:

	rspamc -w <weight> -f <flag> fuzzy_add ...

or delete hashes:

	rspamc -f <flag> fuzzy_del ...

