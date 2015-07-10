# Test rspamd gtube using scan file feature

. ${TEST_DIRNAME}/functions.sh

export RSPAMD_CONFIG="$TEST_DIRNAME/configs/trivial.conf"
run_rspamd
run perl "$TEST_DIRNAME/cases/scan_file.pl" "$TEST_DIRNAME/messages/gtube.eml"
check_output 'GTUBE'