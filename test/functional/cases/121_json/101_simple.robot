*** Settings ***
Suite Setup     JSON Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        lib.robot
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/lua_test.conf
${LUA_SCRIPT}   ${TESTDIR}/lua/simple.lua
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
Stat
  Stat Test

History
  History Test  SIMPLE_TEST

Scan
  Scan Test
