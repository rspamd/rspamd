# Included from top-level .conf file

level = "info";
log_format =<<EOD
id: <$mid>,$if_qid{ qid: <$>,}$if_ip{ ip: $,}$if_user{ user: $,}$if_smtp_from{ from: <$>,}
(default: $is_spam ($action): [$scores] [$symbols_scores_params]),
len: $len, time: $time_real real, $time_virtual virtual, dns req: $dns_req,
digest: <$digest>$if_smtp_rcpts{, rcpts: <$>}$if_mime_rcpt{, mime_rcpt: <$>}
EOD


# Show statistics for regular expressions
log_re_cache = true;

# Can be used for console logging
color = false

# Enable debug for specific modules (e.g. `debug_modules = ["dkim", "re_cache"];`)
debug_modules = []
