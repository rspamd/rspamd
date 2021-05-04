*** Settings ***
Documentation    Test the case when trying to connect to nowhere
...              (i.e. redis is not running)
Test Setup      Dead Redis Setup
Test Teardown   Normal Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py
Suite Teardown  Terminate All Processes    kill=True


*** Variables ***
${REDIS_SCOPE}  Test
${RSPAMD_SCOPE}  Test
${CONFIG}       ${TESTDIR}/configs/redis.conf
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml


*** Test Cases ***
Dead Redis client
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  REDIS_ERROR_3  Connection refused
  Expect Symbol With Exact Options  REDIS_ASYNC201809_ERROR  Connection refused
  Expect Symbol With Exact Options  REDIS_ASYNC_ERROR  Connection refused

*** Keywords ***
Dead Redis Setup
  New Setup  LUA_SCRIPT=${TESTDIR}/lua/redis.lua
