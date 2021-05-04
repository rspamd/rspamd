*** Settings ***
Test Setup      Redis Setup
Test Teardown   Normal Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py
Suite Teardown  Terminate All Processes    kill=True


*** Variables ***
${REDIS_SCOPE}  Test
${RSPAMD_SCOPE}  Test
${CONFIG}       ${RSPAMD_TESTDIR}/configs/redis.conf
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/redis.lua
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${MESSAGE}      ${RSPAMD_TESTDIR}/messages/spam_message.eml


*** Test Cases ***
Redis client
  Redis SET  test_key  test value
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  REDIS  hello from lua on redis
  Expect Symbol With Exact Options  REDIS_ASYNC  test value
  Expect Symbol With Exact Options  REDIS_ASYNC201809  test value

*** Keywords ***
Redis Setup
  Run Redis
  New Setup
