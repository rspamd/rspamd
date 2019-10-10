*** Settings ***
Test Setup      Redis Setup
Test Teardown   Redis Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py
Suite Teardown  Terminate All Processes    kill=True


*** Variables ***
${REDIS_SCOPE}  Test
${RSPAMD_SCOPE}  Test
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml


*** Test Cases ***
Redis client
  Redis SET  test_key  test value
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  REDIS (0.00)[hello from lua on redis]
  Check Rspamc  ${result}  REDIS_ASYNC (0.00)[test value]
  Check Rspamc  ${result}  REDIS_ASYNC201809 (0.00)[test value]

*** Keywords ***
Lua Setup
  [Arguments]  ${LUA_SCRIPT}
  Set Suite Variable  ${LUA_SCRIPT}
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/redis.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG

Redis Setup
  Lua Setup  ${TESTDIR}/lua/redis.lua
  Run Redis

Redis Teardown
  Normal Teardown
  Shutdown Process With Children  ${REDIS_PID}
