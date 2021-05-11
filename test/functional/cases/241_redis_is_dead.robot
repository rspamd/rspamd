*** Settings ***
Documentation    Test the case when trying to connect to nowhere
...              (i.e. redis is not running)
Test Setup      Rspamd Setup
Test Teardown   Rspamd Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py


*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/redis.conf
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}        Test
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/redis.lua
${RSPAMD_SCOPE}       Test
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat


*** Test Cases ***
Dead Redis client
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  REDIS_ERROR_3  Connection refused
  Expect Symbol With Exact Options  REDIS_ASYNC201809_ERROR  Connection refused
  Expect Symbol With Exact Options  REDIS_ASYNC_ERROR  Connection refused
