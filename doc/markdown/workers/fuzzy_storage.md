# Fuzzy storage worker

Fuzzy storage worker is intended to store fuzzy hashes of messages.

## Protocol format

Fuzzy storage accepts requests using `UDP` protocol with the following structure:

~~~C
struct fuzzy_cmd  { /* attribute(packed) */
	unit8_t version;        /* command version, must be 0x2 */
	unit8_t cmd;            /* numeric command */
	unit8_t shingles_count; /* number of shingles */
	unit8_t flag;           /* flag number */
	int32_t value;          /* value to store */
	uint32_t tag;           /* random tag */
	char digest[64];        /* blake2b digest */
};
~~~

All numbers are in host byte order, so if you want to check fuzzy hashes from a
host with different byte order you need some additional conversions (not currently
supported by rspamd). In future, rspamd might use little endian byte order for all
operations.

Fuzzy storage accepts the following commands:
- `FUZZY_CHECK` - check for a fuzzy hash
- `FUZZY_ADD` - add a new hash
- `FUZZY_DEL` - remove a hash

`flag` field is used to store different hashes in a single storage. For example,
it allows to store blacklists and whitelists in the same fuzzy storage worker. 
A client should set the `flag` field when adding or deleting hashes and check it
when querying for a hash.

`value` is added to the currently stored value of a hash if that hash has been found.
This field can handle negative numbers as well.

`tag` is used to distinguish requests by a client. Fuzzy storage just sets this
field in the reply equal to the value in the request.

`digest` field contains the content of hash. Currently, rspamd uses `blake2b` hash
in its binary form granting the `2^512` of possible hashes with negligible collisions
probability. At the same time, rspamd saves the legacy format of fuzzy hashes by
means of this field. Old rspamd can work with legacy hashes only.

`shingles_count` defines how many `shingles` are attached to this command.
Currently, rspamd uses 32 shingles and this value thus should be 32 for commands
with shingles. Shingles should be included in the same packet and follow the command as
an array of int64_t values. Please note, that rspamd rejects commands that have wrong
shingles count or their size is not equal to the desired one:

	sizeof(fuzzy_cmd) + shingles_count * sizeof(int64_t)
	
Reply format of fuzzy storage is also presented as a structure:

~~~C
struct fuzzy_cmd  { /* attribute(packed) */
	int32_t value;
	uint32_t flag;
	uint32_t tag;
	float prob;
};
~~~

`prob` field is used to store the probability of match. This value is changed from
`0.0` (no match) to `1.0` (full match).

## Storage format

Rspamd fuzzy storage uses `sqlite3` for storing hashes. All update operations are
performed in a transaction which is committed to the main database approximately once
per minute. `VACUUM` command is executed on startup and hashes expiration is performed
at the termination of rspamd fuzzy storage worker.

Here is the internal database structure:

```
CREATE TABLE digests(id INTEGER PRIMARY KEY,
	flag INTEGER NOT NULL,
	digest TEXT NOT NULL,
	value INTEGER,
	time INTEGER);
	
CREATE TABLE shingles(value INTEGER NOT NULL,
	number INTEGER NOT NULL,
	digest_id INTEGER REFERENCES digests(id) ON DELETE CASCADE ON UPDATE CASCADE);
```

Since rspamd uses normal sqlite3 you can use all tools for working with the hashes
database to perform, for example backup or analysis.

## Operation notes

To check a hash, rspamd fuzzy storage initially queries for the direct match using
`digest` field as a key. If that match succeed then the value is returned immediately.
Otherwise, if a command contains shingles then rspamd checks for fuzzy match trying
to find each shingle's value. If more than 50% of shingles matches the same digest
then rspamd returns that digest's value and the probability of match that means
generally `match_count / shingles_count`.

## Configuration

Fuzzy storage accepts the following extra options:

- `database` - path to the sqlite storage
- `expire` - time value for hashes expiration
- `allow_map` - string, array of strings or a map of IP addresses that are allowed
to perform changes to fuzzy storage

Here is an example configuration of fuzzy storage:

~~~nginx
worker {
   type = "fuzzy";
   bind_socket = "*:11335";
   hash_file = "${DBDIR}/fuzzy.db"
   expire = 90d;
   allow_update = "127.0.0.1";
}
~~~

## Compatibility notes

Rspamd fuzzy storage of version `0.8` can work with rspamd clients of all versions,
however, all updates from legacy versions (less that `0.8`) won't update fuzzy shingles
database. Rspamd [fuzzy check module](../modules/fuzzy_check.md) can work **only**
with the recent rspamd fuzzy storage (it won't get anything from the legacy storages).