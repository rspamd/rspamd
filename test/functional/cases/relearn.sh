# Test rspamd re-learn

. ${TEST_DIRNAME}/functions.sh

export RSPAMD_CONFIG="$TEST_DIRNAME/configs/stats.conf" \
	STATSDIR=${TMPDIR}

run_rspamd
run_rspamc learn_spam \
	 --key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
	"$TEST_DIRNAME/messages/spam_message.eml"
check_output 'success.*true'
	
run_rspamc symbols \
	 --key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
	"$TEST_DIRNAME/messages/spam_message.eml"
check_output 'BAYES_SPAM'

run_rspamc learn_ham \
	 --key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
	"$TEST_DIRNAME/messages/spam_message.eml"
check_output 'success.*true'
	
run_rspamc symbols \
	 --key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
	"$TEST_DIRNAME/messages/spam_message.eml"
check_output 'BAYES_HAM'