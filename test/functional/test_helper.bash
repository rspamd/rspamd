function run_rspamd() {
	RSPAMD_USER=${RSPAMD_USER:-"nobody"}
	RSPAMD_GROUP=${RSPAMD_GROUP:-"nogroup"}
	RSPAMD=${RSPAMD:-"$BATS_TEST_DIRNAME/../../src/rspamd"}
	
	${RSPAMD} -c ${RSPAMD_CONFIG} -u ${RSPAMD_USER} -g ${RSPAMD_GROUP}
}


function teardown() {
	pkill -TERM rspamd
}
