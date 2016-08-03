*** Settings ***
Suite Setup     Generic Setup
Suite Teardown  Generic Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/lua_test.conf
${LUA_SCRIPT}   ${TESTDIR}/lua/preresult.lua
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
Stat
  @{result} =  HTTP  GET  ${LOCAL_ADDR}  ${PORT_CONTROLLER}  /stat
  Check JSON  @{result}[1]

History
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  soft reject
  @{result} =  HTTP  GET  ${LOCAL_ADDR}  ${PORT_CONTROLLER}  /history
  Check JSON  @{result}[1]

Scan
  ${content} =  Get File  ${MESSAGE}
  @{result} =  HTTP  POST  ${LOCAL_ADDR}  ${PORT_NORMAL}  /check  ${content}
  Check JSON  @{result}[1]
