# Test rspamd learn using xxhash

. ${TEST_DIRNAME}/functions.sh

export RSPAMD_CONFIG="$TEST_DIRNAME/configs/stats.conf" \
	STATSDIR=${TMPDIR} \
	STATS_HASH="xxh"

run_rspamd
run_rspamc learn_spam \
	 --key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
	"$BATS_TEST_DIRNAME/messages/spam_message.eml"
check_output $output 'success.*true'
	
run_rspamc symbols \
	 --key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
	"$BATS_TEST_DIRNAME/messages/spam_message.eml"
check_output $output 'BAYES_SPAM'