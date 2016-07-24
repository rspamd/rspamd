# Included from top-level .conf file

level = "info";
log_format =<<EOD
id: <$mid>,$if_qid{ qid: <$>,}$if_ip{ ip: $,}$if_user{ user: $,}$if_smtp_from{ from: <$>,}
(default: $is_spam ($action): [$scores] [$symbols_scores]),
len: $len, time: $time_real real,
$time_virtual virtual, dns req: $dns_req
EOD
