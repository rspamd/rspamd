# Test rspamd using gtube

. ${TEST_DIRNAME}/functions.sh

export RSPAMD_CONFIG="$TEST_DIRNAME/configs/trivial.conf"
run_rspamd
run_rspamc symbols "$TEST_DIRNAME/messages/gtube.eml"
check_output "$output" 'Action: reject'