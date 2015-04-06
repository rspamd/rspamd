# Included from top-level .conf file

filters = "chartable,dkim,spf,surbl,regexp,fuzzy_check";
raw_mode = false;
one_shot = false;
cache_file = "$DBDIR/symbols.cache";
map_watch_interval = 1min;
dynamic_conf = "$DBDIR/rspamd_dynamic";
history_file = "$DBDIR/rspamd.history";
check_all_filters = false;
dns {
    timeout = 1s;
    sockets = 16;
    retransmits = 5;
}
tempdir = "/tmp";
url_tld = "${PLUGINSDIR}/effective_tld_names.dat";