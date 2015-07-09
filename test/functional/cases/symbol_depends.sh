# Test rspamd symbol dependencies

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