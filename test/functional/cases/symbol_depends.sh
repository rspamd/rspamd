# Test rspamd symbol dependencies

. ${TEST_DIRNAME}/functions.sh

sed -e 's|@@LUA_SCRIPT@@|${CURDIR}/functional/cases/deps.lua|' < \
	"$TEST_DIRNAME/configs/lua_test.conf" > \
	"$TMPDIR/rspamd.conf"
export RSPAMD_CONFIG="$TMPDIR/rspamd.conf" \
	STATSDIR=${TMPDIR}
run_rspamd

run_rspamc symbols \
	"$BATS_TEST_DIRNAME/messages/spam_message.eml"
check_output $output 'DEP10'