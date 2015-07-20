# Test rspamd reload

. ${TEST_DIRNAME}/functions.sh

sed -e 's|@@LUA_SCRIPT@@|${TESTDIR}/cases/deps.lua|' < \
	"$TEST_DIRNAME/configs/lua_test.conf" > \
	"$TMPDIR/rspamd.conf"
export RSPAMD_CONFIG="$TMPDIR/rspamd.conf" \
	STATSDIR=${TMPDIR}
run_rspamd

run_rspamc symbols \
	"$TEST_DIRNAME/messages/spam_message.eml"
check_output 'DEP10'

kill -HUP `cat ${TMPDIR}/rspamd.pid`
sleep 0.5
kill -HUP `cat ${TMPDIR}/rspamd.pid`
sleep 0.5

run_rspamc symbols \
	"$TEST_DIRNAME/messages/spam_message.eml"
check_output 'DEP10'