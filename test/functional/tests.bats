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

@test "Test rspamd encrypted using gtube" {
	export RSPAMD_CONFIG="$BATS_TEST_DIRNAME/configs/trivial.conf"
	run_rspamd
	run ${RSPAMC} -h localhost:56789 \
		--key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
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
	skip
	export RSPAMD_CONFIG="$BATS_TEST_DIRNAME/configs/trivial.conf"
	run_rspamd
	run perl $BATS_TEST_DIRNAME/cases/http_streamline.pl "$BATS_TEST_DIRNAME/messages/gtube.eml"
	[ "$status" -eq 0 ]
	
	echo $output | grep 'Action: reject'
}

@test "Test rspamd learn" {
	export RSPAMD_CONFIG="$BATS_TEST_DIRNAME/configs/stats.conf" \
		STATSDIR=${BATS_TMPDIR}
	clear_stats
	run_rspamd
	run ${RSPAMC} -h localhost:56790 \
		--key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
		learn_spam \
		"$BATS_TEST_DIRNAME/messages/spam_message.eml"
	[ "$status" -eq 0 ]
	
	echo $output | egrep 'success.*true'
	
	run ${RSPAMC} -h localhost:56789 \
		--key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
		symbols \
		"$BATS_TEST_DIRNAME/messages/spam_message.eml"
	[ "$status" -eq 0 ]
	
	echo $output | grep 'BAYES_SPAM'
	clear_stats
}

@test "Test rspamd re-learn" {
	export RSPAMD_CONFIG="$BATS_TEST_DIRNAME/configs/stats.conf" \
		STATSDIR=${BATS_TMPDIR}
	clear_stats
	run_rspamd
	run ${RSPAMC} -h localhost:56790 \
		--key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
		learn_spam \
		"$BATS_TEST_DIRNAME/messages/spam_message.eml"
	[ "$status" -eq 0 ]
	
	echo $output | egrep 'success.*true'
	
	run ${RSPAMC} -h localhost:56790 \
		--key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
		learn_ham \
		"$BATS_TEST_DIRNAME/messages/spam_message.eml"
	[ "$status" -eq 0 ]
	
	echo $output | egrep 'success.*true'
	
	run ${RSPAMC} -h localhost:56789 \
		--key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
		symbols \
		"$BATS_TEST_DIRNAME/messages/spam_message.eml"
	[ "$status" -eq 0 ]
	
	echo $output | grep 'BAYES_HAM'
	clear_stats
}

@test "Test learn message with an empty part" {
	export RSPAMD_CONFIG="$BATS_TEST_DIRNAME/configs/stats.conf" \
		STATSDIR=${BATS_TMPDIR}
	clear_stats
	run_rspamd
	run ${RSPAMC} -h localhost:56790 \
		--key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
		learn_spam \
		"$BATS_TEST_DIRNAME/messages/empty_part.eml"
	[ "$status" -eq 0 ]
	
	echo $output | egrep 'success.*true'
	
	run ${RSPAMC} -h localhost:56789 \
		--key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
		symbols \
		"$BATS_TEST_DIRNAME/messages/empty_part.eml"
	[ "$status" -eq 0 ]
	
	echo $output | grep 'BAYES_SPAM'
	clear_stats
}

@test "Test rspamd re-learn sqlite3 backend" {
	export RSPAMD_CONFIG="$BATS_TEST_DIRNAME/configs/stats.conf" \
		STATSDIR=${BATS_TMPDIR} \
		STATS_BACKEND="sqlite3"
	clear_stats
	run_rspamd
	run ${RSPAMC} -h localhost:56790 \
		--key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
		learn_spam \
		"$BATS_TEST_DIRNAME/messages/spam_message.eml"
	[ "$status" -eq 0 ]
	
	echo $output | egrep 'success.*true'
	
	run ${RSPAMC} -h localhost:56790 \
		--key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
		learn_ham \
		"$BATS_TEST_DIRNAME/messages/spam_message.eml"
	[ "$status" -eq 0 ]
	
	echo $output | egrep 'success.*true'
	
	run ${RSPAMC} -h localhost:56789 \
		--key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
		symbols \
		"$BATS_TEST_DIRNAME/messages/spam_message.eml"
	[ "$status" -eq 0 ]
	
	echo $output | grep 'BAYES_HAM'
	clear_stats
}

@test "Test learn message with bad statfiles" {
	export RSPAMD_CONFIG="$BATS_TEST_DIRNAME/configs/stats.conf" \
		STATSDIR=/non/existent
	run_rspamd
	run ${RSPAMC} -h localhost:56790 \
		--key y3ms1knmetxf8gdeixkf74b6tbpxqugmxzqksnjodiqei7tksyty \
		learn_spam \
		"$BATS_TEST_DIRNAME/messages/empty_part.eml"
	[ "$status" -eq 0 ]
	
	echo $output >&2
	echo $output | egrep 'cannot open backend'
}

@test "Test rspamd dependencies" {
	sed -e 's|@@LUA_SCRIPT@@|${CURDIR}/functional/cases/deps.lua|' < \
		"$BATS_TEST_DIRNAME/configs/lua_test.conf" > \
		"$BATS_TMPDIR/rspamd.conf"
	export RSPAMD_CONFIG="$BATS_TMPDIR/rspamd.conf" \
		STATSDIR=${BATS_TMPDIR}
	run_rspamd
	run ${RSPAMC} -h localhost:56789 \
		symbols \
		"$BATS_TEST_DIRNAME/messages/spam_message.eml"
	[ "$status" -eq 0 ]
	
	echo $output | grep 'DEP10'
}