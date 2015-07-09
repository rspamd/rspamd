#!/bin/sh

TMPDIR=
RSPAMD_PID=
TEST_DIRNAME=`cd $(dirname $0) ; pwd`
TEST_NAME='top'
TEST_DESCRIPTION='no description'
FAILED_TESTS=0
SUCCESSFUL_TESTS=0
SKIPPED_TESTS=0

. ${TEST_DIRNAME}/functions.sh

make_tempdir() {
	export TMPDIR=`mktemp -d /tmp/rspamd-test-XXXXXX`
}

run_test() {
	TEST_NAME=`basename $1 | sed -e 's/.sh$//'`
	TEST_DESCRIPTION=`head -1 $1 | sed -e 's/^# *//'`

	printf '%s: ' "${TEST_DESCRIPTION}"

	egrep '^skip$' $1
	if [ $? -eq 0 ] ; then
		SKIPPED_TESTS=$(($SKIPPED_TESTS + 1))
		echo "SKIP"
		return 0
	fi

	make_tempdir
	export TEST_NAME TMPDIR TEST_DESCRIPTION TEST_DIRNAME
	sh "$1"

	if [ $? -ne 0 ] ; then
		FAILED_TESTS=$(($FAILED_TESTS + 1))
		echo "FAIL"
	else
		SUCCESSFUL_TESTS=$(($SUCCESSFUL_TESTS + 1))
		if [ -d /tmp/rspamd-failed-tests/${TEST_NAME} ] ; then
			rm -fr /tmp/rspamd-failed-tests/${TEST_NAME}
		fi
		echo "OK"
	fi

	teardown
}

if [ $# -ne 0 ] ; then
	for _test in $@ ; do
		run_test $_test
	done
else
	for _test in ${TEST_DIRNAME}/cases/*.sh ; do
		run_test $_test
	done
	
fi

echo "Successful tests: $SUCCESSFUL_TESTS; failed tests: $FAILED_TESTS, skipped tests: $SKIPPED_TESTS"