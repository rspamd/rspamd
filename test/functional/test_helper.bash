function run_rspamd() {
	RSPAMD_USER=${RSPAMD_USER:-"nobody"}
	RSPAMD_GROUP=${RSPAMD_GROUP:-"nogroup"}
	RSPAMD=${RSPAMD:-"$BATS_TEST_DIRNAME/../../src/rspamd"}
	
	if [ -f /tmp/rspamd-bats.log ] ; then rm -f /tmp/rspamd-bats.log ; fi
	${RSPAMD} -c ${RSPAMD_CONFIG} -u ${RSPAMD_USER} -g ${RSPAMD_GROUP}
}


function teardown() {
	pkill -TERM rspamd
}

function clear_stats() {
	rm -f /tmp/rspamd-bats-cache.sqlite /tmp/rspamd-bats-bayes.spam /tmp/rspamd-bats-bayes.ham || true	
}
