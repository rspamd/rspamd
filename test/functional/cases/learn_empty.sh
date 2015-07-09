# Test rspamd learn empty part

. ${TEST_DIRNAME}/functions.sh

export RSPAMD_CONFIG="$TEST_DIRNAME/configs/stats.conf" \
	STATSDIR=${TMPDIR}

run_rspamd
run_rspamc learn_spam \
	 --key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
	"$BATS_TEST_DIRNAME/messages/empty_part.eml"
check_output $output 'success.*true'
	
run_rspamc symbols \
	 --key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
	"$BATS_TEST_DIRNAME/messages/empty_part.eml"
check_output $output 'BAYES_SPAM'