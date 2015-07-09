TMPDIR=${BATS_TMPDIR}

function run_rspamd() {
	TMPDIR=${BATS_TMPDIR}
	RSPAMD_USER=${RSPAMD_USER:-"nobody"}
	RSPAMD_GROUP=${RSPAMD_GROUP:-"nogroup"}
	RSPAMD=${RSPAMD:-"$BATS_TEST_DIRNAME/../../src/rspamd"}
	STATS_BACKEND=${STATS_BACKEND:-"mmap"}
	STATS_HASH=${STATS_HASH:-"compat"}
	STATS_KEY=${STATS_KEY:-"osipg87ms5gzsis33fdrhaqn5wocp6qfofzxjbw8k1wh9yb6adty"}
	
	if [ -f ${TMPDIR}/rspamd-bats-${BATS_TEST_NAME}.log ] ; then 
		rm -f ${TMPDIR}/rspamd-bats-${BATS_TEST_NAME}.log
	fi
	${RSPAMD} -c ${RSPAMD_CONFIG} -u ${RSPAMD_USER} -g ${RSPAMD_GROUP} \
		TMPDIR=${TMPDIR} \
		STATSDIR=${STATSDIR} \
		LUADIR=${LUADIR} \
		TEST_NUM=${BATS_TEST_NAME} \
		STATS_BACKEND=${STATS_BACKEND} \
		STATS_HASH=${STATS_HASH} \
		STATS_KEY=${STATS_KEY}
}


function teardown() {
	( 
	pgrep rspamd > /dev/null 2>&1
	while [ $? -eq 0 ] ; do
		pkill -TERM rspamd || true 
		pgrep rspamd > /dev/null 2>&1
		if [ $? -eq 0 ] ; then
			sleep 0.1
		fi
		pgrep rspamd > /dev/null 2>&1
	done
	) || true
}

function clear_stats() {
	rm -f ${STATSDIR}/rspamd-bats-cache.sqlite \
		${STATSDIR}/rspamd-bats-bayes.spam \
		${STATSDIR}/rspamd-bats-bayes.ham || true	
}

function check_output() {
	_output="$1"
	_pattern="$2"

	( 
	echo $_output | egrep $_pattern
	
	_saved_exit=$?
	if [ $_saved_exit -ne 0 ] ; then
		printf "Expected pattern %s, while get output:\n%s\nEND\n" $_pattern $_output >&2
		return $_saved_exit
	fi

	return 0
	)
}
