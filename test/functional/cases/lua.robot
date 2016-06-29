*** Settings ***
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot

*** Variables ***
${CONFIG}        ${TESTDIR}/configs/lua_test.conf
${MESSAGE}       ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Test

*** Keywords ***
Lua Setup
  [Arguments]  ${lua_script}
  &{RSPAMD_KEYWORDS} =  Create Dictionary  LOCAL_ADDR=${LOCAL_ADDR}  LUA_SCRIPT=${lua_script}  PORT_CONTROLLER=${PORT_CONTROLLER}  PORT_NORMAL=${PORT_NORMAL}  TESTDIR=${TESTDIR}
  Set Test Variable  &{RSPAMD_KEYWORDS}
  Generic Setup

*** Test Cases ***
Flags
  [Setup]  Lua Setup  ${TESTDIR}/lua/flags.lua
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Follow Rspamd Log
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  stat
  Should Contain  ${result.stdout}  Messages scanned: 0
  [Teardown]  Generic Teardown

Dependencies
  [Setup]  Lua Setup  ${TESTDIR}/lua/deps.lua
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  DEP10
  [Teardown]  Generic Teardown
