*** Settings ***
Test Setup      Rspamd Redis Setup
Test Teardown   Rspamd Redis Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py
Suite Teardown  Terminate All Processes    kill=True


*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/redis.conf
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}        Test
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/redis.lua
${RSPAMD_SCOPE}       Test
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat


*** Test Cases ***
Redis client
  Redis SET  test_key  test value
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  REDIS  hello from lua on redis
  Expect Symbol With Exact Options  REDIS_ASYNC  test value
  Expect Symbol With Exact Options  REDIS_ASYNC201809  test value
