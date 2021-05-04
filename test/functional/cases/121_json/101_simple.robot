*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        lib.robot
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/simple.lua
${RSPAMD_SCOPE}       Suite

*** Test Cases ***
Stat
  Stat Test

History
  History Test  SIMPLE_TEST

Scan
  Scan Test
