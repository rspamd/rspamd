save_error() {
	_where=$1
	_reason=$2

	printf 'Failed in %s: %s\n' "$_where" "$_reason" > ${TMPDIR}/test.err
	mkdir -p /tmp/rspamd-failed-tests/${TEST_NAME} || true
	# Save logs
	RSPAMD_PID=`cat ${TMPDIR}/rspamd.pid`

	if [ F"${RSPAMD_PID}" != F"" ] ; then
		kill -USR1 ${RSPAMD_PID} > /dev/null 2>&1
		sleep 0.5
	fi
	cp -rf ${TMPDIR}/* /tmp/rspamd-failed-tests/${TEST_NAME}

	exit 1
}

run_rspamd() {
	RSPAMD_USER=${RSPAMD_USER:-"nobody"}
	RSPAMD_GROUP=${RSPAMD_GROUP:-"nogroup"}
	RSPAMD=${RSPAMD:-"$TEST_DIRNAME/../../src/rspamd"}
	STATS_BACKEND=${STATS_BACKEND:-"mmap"}
	STATS_HASH=${STATS_HASH:-"compat"}
	STATS_KEY=${STATS_KEY:-"osipg87ms5gzsis33fdrhaqn5wocp6qfofzxjbw8k1wh9yb6adty"}
	
	${RSPAMD} -c ${RSPAMD_CONFIG} -u ${RSPAMD_USER} -g ${RSPAMD_GROUP} -t \
		TMPDIR=${TMPDIR} \
		STATSDIR=${STATSDIR} \
		LUADIR=${LUADIR} \
		STATS_BACKEND=${STATS_BACKEND} \
		STATS_HASH=${STATS_HASH} \
		TESTDIR=${TEST_DIRNAME} \
		STATS_KEY=${STATS_KEY} > ${TMPDIR}/rspamd.out 2>&1

	if [ $? -ne 0 ] ; then
		save_error 'rspamd' 'cannot lint rspamd configuration'
	fi

	${RSPAMD} -c ${RSPAMD_CONFIG} -u ${RSPAMD_USER} -g ${RSPAMD_GROUP} \
		TMPDIR=${TMPDIR} \
		STATSDIR=${STATSDIR} \
		LUADIR=${LUADIR} \
		STATS_BACKEND=${STATS_BACKEND} \
		STATS_HASH=${STATS_HASH} \
		TESTDIR=${TEST_DIRNAME} \
		STATS_KEY=${STATS_KEY} >> ${TMPDIR}/rspamd.out 2>&1

	if [ $? -eq 0 ] ; then
		export RSPAMD_PID=`cat ${TMPDIR}/rspamd.pid`
	else
		save_error 'rspamd' 'cannot start rspamd'
	fi
}


teardown() {
	RSPAMD_PID=`cat ${TMPDIR}/rspamd.pid`

	if [ F"${RSPAMD_PID}" != F"" ] ; then
		kill -TERM ${RSPAMD_PID} > /dev/null 2>&1

		while [ $? -eq 0 ] ; do
			sleep 0.1
			kill -0 ${RSPAMD_PID} > /dev/null 2>&1
			if [ $? -eq 0 ] ; then
				kill -TERM ${RSPAMD_PID} > /dev/null 2>&1
			fi
			kill -0 ${RSPAMD_PID} > /dev/null 2>&1
		done
	fi

	if [ -d "${TMPDIR}" ] ; then
		(echo "${TMPDIR}" | egrep '^/tmp.*$' > /dev/null 2>&1) && rm -fr "${TMPDIR}"
	fi
}

check_output() {
	_pattern="$1"

	echo "$output" | egrep "$_pattern" > /dev/null 2>&1
	
	_saved_exit=$?
	if [ $_saved_exit -ne 0 ] ; then
		echo "$output" > ${TMPDIR}/rspamc.err
		save_error 'rspamc' "Expected pattern $_pattern is not found"
		return $_saved_exit
	fi

	return 0
}

run_rspamc() {
	_command=$1
	shift
	_rspamc="$TEST_DIRNAME/../../src/client/rspamc"

	case $_command in
		learn_spam|learn_ham|fuzzy_add|fuzzy_del|stat) _host="localhost:56790" ;;
		*) _host="localhost:56789" ;;
	esac

	output=`$_rspamc -h $_host $_command $@ 2>&1`
	echo "$output" > ${TMPDIR}/rspamc.output

	if [ $? -eq 0 ] ; then
		export output
		return 0
	else
		save_error 'rspamc' "Wrong exit code"
	fi

	return 1
}

run() {
	_command=$1
	shift

	output=`$_command $@ 2>&1`
	echo "$output" > "${TMPDIR}/${_command}.output"

	if [ $? -eq 0 ] ; then
		export output
		return 0
	else
		save_error "${_command}" "Wrong exit code"
	fi

	return 1
}