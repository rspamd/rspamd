# Fuzzy storage worker setup
# Please don't modify this file as your changes might be overwritten with
# the next update.
#
# You can modify 'local.d/worker-fuzzy.inc' to add and merge
# parameters defined inside this section
#
# You can modify 'override.d/worker-fuzzy.inc' to strictly override all
# parameters defined inside this section
#
# See https://rspamd.com/doc/faq.html#what-are-the-locald-and-overrided-directories
# for details
# Module documentation: https://rspamd.com/doc/workers/fuzzy_storage.html

backend = "redis";

# For sqlite stuff
#backend = "sqlite";
#hash_file = "${DBDIR}/fuzzy.db";

expire = 90d;
allow_update = ["localhost"];

# Customer keys (dynamic keys and non-default static keys) bypass source-IP
# bans and source/network rate limits after successful decryption. Their own
# limits, expiry and operation permissions still apply. The default keypair
# (the last static keypair, if several are configured) retains IP-based policy.
# Override this per key with extensions { skip_ip_checks = true/false; }.
# Banned requests are parsed for telemetry and then silently dropped: pre-handler
# extensions, aggregate counters and enabled per-key/IP error counters are kept.

# Redis backend: the number of stored hashes is recomputed by a slow, resumable
# keyspace scan run by the first fuzzy worker (the result is shared by all
# storages using the same Redis and prefix)
#count_scan {
#  enabled = true;
#  interval = 4h; # minimum time between completed passes
#  batch = 1000; # SCAN COUNT hint
#  duty_cycle = 0.1; # maximum share of time a SCAN request is outstanding
#  stats_sample = 10; # read 1 in N digests for per-flag/shingles/age statistics, 0 disables
#}
