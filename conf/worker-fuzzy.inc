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