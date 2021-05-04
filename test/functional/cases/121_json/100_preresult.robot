*** Settings ***
Suite Setup     JSON Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        lib.robot
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/lua_test.conf
${LUA_SCRIPT}   ${TESTDIR}/lua/preresult.lua
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
Stat
  Stat Test

History
  History Test  soft reject

Scan
  Scan Test
