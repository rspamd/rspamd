*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${SETTINGS_REDIS}     {symbols_enabled = [REDIS_TEST, SIMPLE_REDIS_ASYNC_TEST, SIMPLE_REDIS_ASYNC201809_TEST]}

*** Test Cases ***
Redis client
  Redis SET  test_key  test value
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_REDIS}
  Expect Symbol With Exact Options  REDIS  hello from lua on redis
  Expect Symbol With Exact Options  REDIS_ASYNC  test value
  Expect Symbol With Exact Options  REDIS_ASYNC201809  test value

Redis pooled connections
  [Documentation]  Nothing of a request stays on a connection; a setup that fails is an error
  Redis SET  test_key  test value
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [REDIS_POOL_TEST]}
  Expect Symbol  REDIS_POOL_OK
  Do Not Expect Symbol  REDIS_POOL_FAIL
