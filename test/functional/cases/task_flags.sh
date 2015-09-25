# Test rspamd_task:get|set_flags functions

. ${TEST_DIRNAME}/functions.sh

sed -e 's|@@LUA_SCRIPT@@|${TESTDIR}/cases/flags.lua|' < \
	"$TEST_DIRNAME/configs/lua_test.conf" > \
	"$TMPDIR/rspamd.conf"
export RSPAMD_CONFIG="$TMPDIR/rspamd.conf" \
	STATSDIR=${TMPDIR}
run_rspamd

run_rspamc symbols \
	"$TEST_DIRNAME/messages/spam_message.eml"
check_output 'skip,extended_urls,no_log,no_stat'

run_rspamc stat
check_output 'Messages scanned: 0'