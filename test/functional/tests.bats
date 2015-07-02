load test_helper

RSPAMC="$BATS_TEST_DIRNAME/../../src/client/rspamc"

@test "Test rspamd using gtube" {
	export RSPAMD_CONFIG="$BATS_TEST_DIRNAME/configs/trivial.conf"
	run_rspamd
	run ${RSPAMC} -h localhost:56789 \
		"$BATS_TEST_DIRNAME/messages/gtube.eml"
	[ "$status" -eq 0 ]
	
	echo $output | grep 'Action: reject'
}

@test "Test rspamd spamc gtube" {
	export RSPAMD_CONFIG="$BATS_TEST_DIRNAME/configs/trivial.conf"
	run_rspamd
	run perl $BATS_TEST_DIRNAME/cases/spamc.pl "$BATS_TEST_DIRNAME/messages/gtube.eml"
	[ "$status" -eq 0 ]
	
	echo $output | grep 'GTUBE'
}

@test "Test rspamd streamlined gtube" {
	export RSPAMD_CONFIG="$BATS_TEST_DIRNAME/configs/trivial.conf"
	run_rspamd
	run perl $BATS_TEST_DIRNAME/cases/http_streamline.pl "$BATS_TEST_DIRNAME/messages/gtube.eml"
	[ "$status" -eq 0 ]
	
	echo $output | grep 'Action: reject'
}