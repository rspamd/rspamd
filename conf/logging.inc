# Logging configuration
# Please don't modify this file as your changes might be overwritten with
# the next update.
#
# You can modify 'local.d/logging.inc' to add and merge
# parameters defined inside this section
#
# You can modify 'override.d/logging.inc' to strictly override all
# parameters defined inside this section
#
# See https://rspamd.com/doc/faq.html#what-are-the-locald-and-overrided-directories
# for details
#
# Relevant documentation: https://rspamd.com/doc/configuration/logging.html

level = "info";
log_format =<<EOD
id: <$mid>,$if_qid{ qid: <$>,}$if_ip{ ip: $,}$if_user{ user: $,}$if_smtp_from{ from: <$>,}
(default: $is_spam ($action): [$scores] [$symbols_scores_params]),
len: $len, time: $time_real, dns req: $dns_req,
digest: <$digest>$if_smtp_rcpts{, rcpts: <$>}$if_mime_rcpts{, mime_rcpts: <$>}$if_filename{, file: $}$if_forced_action{, forced: $}$if_settings_id{, settings_id: $}
EOD


# Show statistics for regular expressions
log_re_cache = true;

# Can be used for console logging
color = false;

# Log with microseconds resolution
log_usec = false;

# Enable debug for specific modules (e.g. `debug_modules = ["dkim", "re_cache"];`)
debug_modules = []
