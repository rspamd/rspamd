*** Settings ***
Test Teardown   Generic Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/lua_test.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Test

*** Test Cases ***
Flags
  [Setup]  Lua Setup  ${TESTDIR}/lua/flags.lua
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Follow Rspamd Log
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  stat
  Should Contain  ${result.stdout}  Messages scanned: 0

Dependencies
  [Setup]  Lua Setup  ${TESTDIR}/lua/deps.lua
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  DEP10

Pre and Post Filters
  [Setup]  Lua Setup  ${TESTDIR}/lua/prepostfilters.lua
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  TEST_PRE
  Should Contain  ${result.stdout}  TEST_POST

*** Keywords ***
Lua Setup
  [Arguments]  ${LUA_SCRIPT}
  Set Test Variable  ${LUA_SCRIPT}
  Generic Setup
