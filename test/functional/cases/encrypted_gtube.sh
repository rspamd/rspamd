# Test rspamd encrypted using gtube

. ${TEST_DIRNAME}/functions.sh

export RSPAMD_CONFIG="$TEST_DIRNAME/configs/trivial.conf"
run_rspamd
run_rspamc symbols --key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
	"$TEST_DIRNAME/messages/gtube.eml"
check_output 'Action: reject'