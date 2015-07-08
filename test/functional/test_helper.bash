TMPDIR=${BATS_TMPDIR}

function run_rspamd() {
	TMPDIR=${BATS_TMPDIR}
	RSPAMD_USER=${RSPAMD_USER:-"nobody"}
	RSPAMD_GROUP=${RSPAMD_GROUP:-"nogroup"}
	RSPAMD=${RSPAMD:-"$BATS_TEST_DIRNAME/../../src/rspamd"}
	
	if [ -f ${TMPDIR}/rspamd-bats.log ] ; then rm -f ${TMPDIR}/rspamd-bats.log ; fi
	${RSPAMD} -c ${RSPAMD_CONFIG} -u ${RSPAMD_USER} -g ${RSPAMD_GROUP} TMPDIR=${TMPDIR}
}


function teardown() {
	( 
	pgrep rspamd > /dev/null 2>&1
	while [ $? -eq 0 ] ; do
		pkill -TERM rspamd || true 
		pgrep rspamd > /dev/null 2>&1
	done
	) || true
}

function clear_stats() {
	rm -f ${TMPDIR}/rspamd-bats-cache.sqlite ${TMPDIR}/rspamd-bats-bayes.spam ${TMPDIR}/rspamd-bats-bayes.ham || true	
}
